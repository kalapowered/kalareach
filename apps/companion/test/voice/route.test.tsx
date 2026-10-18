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

import closures from '../fixtures/voice-stop-closures.json'

import { AppProvider } from '../../src/app/state'
import { fakeHost, type FakeHostControls } from '../../src/host/fake'
import type { HostPort, VoiceClosure } from '../../src/host/port'
import { VoiceRoute } from '../../src/voice/VoiceRoute'

/** The session the fake host's workers answer for. */
const SESSION_MAIN = '8a7b6c50-22bb-4c3d-8e4f-000000000101'

/** The voice calls this screen made, watched from before it was rendered. */
type Watched = Record<
  'voicePrepare' | 'voiceStart' | 'voiceContext' | 'voiceSetMuted',
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
    expect(watched.voiceSetMuted).not.toHaveBeenCalled()
    expect(watched.voicePrepare).toHaveBeenCalledTimes(1)
  })

  // What a grant permits is not what this version carries out, and the person is told so before
  // they start, beside the list of what speaking is allowed to do.
  it('says before a start that this version acts on no spoken request', async () => {
    start()
    await waitForChoice()

    const permits = screen.getByRole('region', { name: 'What speaking will be allowed to do' })
    expect(
      within(permits).getByText('Not done: this version does not act on spoken requests.')
    ).toBeInTheDocument()
  })

  // The device keeps what the last call left, and the screen shows it before another start: the
  // warning from a service that had no such call, and a grant the host may still hold open.
  it('shows the warning and what is owed before a start', async () => {
    start((controls) => {
      controls.setVoiceWarning('The last call found that this voice service has no such call.')
      controls.oweVoice({ words: 'The host did not confirm that it withdrew the grant.' })
    })
    await waitForChoice()

    const left = await screen.findByRole('status', { name: 'The last call' })
    expect(within(left).getByText(/no such call/)).toBeInTheDocument()
    expect(within(left).getByText(/did not confirm that it withdrew the grant/)).toBeInTheDocument()
  })

  // A call that ended while no screen looked is said to have ended, in the device's words, when a
  // screen is shown.
  it('says how a call that ended with no screen looking ended', async () => {
    start((controls) => {
      controls.holdAVoiceCall()
      controls.endVoiceCall({
        cause: 'native_ended',
        words: 'The call ended on this device: from its notification.',
        host: { kind: 'not_told', words: 'The host could not be reached.' }
      })
    })
    await waitForChoice()

    const left = await screen.findByRole('status', { name: 'The last call' })
    expect(within(left).getByText(/from its notification/)).toBeInTheDocument()
    expect(
      within(left).getByText(/The host did not confirm that it withdrew the call's grant/)
    ).toBeInTheDocument()
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

  // Section 9: ending a call is complete for the host once its workers hold the revision that
  // refuses what the call sent. The grant is withdrawn either way, and the screen says which
  // sessions the host has still to confirm instead of reporting a complete stop.
  it('names the sessions the host has still to confirm when the call ends', async () => {
    const person = userEvent.setup()
    const { controls } = start()
    await waitForChoice()
    await person.click(screen.getByRole('button', { name: 'Start voice session' }))
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'End session' })).toBeInTheDocument()
    })

    controls.leaveNextVoiceChangePendingAt([SESSION_MAIN])
    await person.click(screen.getByRole('button', { name: 'End session' }))

    await waitFor(() => {
      expect(
        screen.getByText(/that nothing the call sent can still run in Session 1\./)
      ).toBeInTheDocument()
    })
    expect(screen.getByText(/its grant withdrawn/)).toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: 'Voice session' })).not.toBeInTheDocument()
  })

  // Section 9: a host whose answer gives no status for its workers that this app can read has not
  // shown that they hold, so the screen says that and does not report the stop as complete.
  it('says it cannot confirm the host\'s workers when their status cannot be read', async () => {
    const person = userEvent.setup()
    const { controls } = start()
    await waitForChoice()
    await person.click(screen.getByRole('button', { name: 'Start voice session' }))
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'End session' })).toBeInTheDocument()
    })

    controls.leaveNextVoiceStopFenceUnreadable()
    await person.click(screen.getByRole('button', { name: 'End session' }))

    await waitFor(() => {
      expect(
        screen.getByText(/this app cannot confirm that nothing the call sent can still run/)
      ).toBeInTheDocument()
    })
    expect(screen.getByText(/its grant withdrawn/)).toBeInTheDocument()
    expect(screen.queryByText(/has not yet confirmed/)).not.toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: 'Voice session' })).not.toBeInTheDocument()
  })

  // Section 9: the closures native code gives the page, as native code builds them (the same
  // fixture is read by the native test that builds them), are shown as each says: nothing for a
  // fence the host did not owe or whose workers all hold, the sessions that have not held, and that
  // the app cannot confirm when the host's status could not be read.
  it.each(closures)('shows $name as native code gives it', async ({ closure, notice }) => {
    const person = userEvent.setup()
    const { port } = start()
    await waitForChoice()
    await person.click(screen.getByRole('button', { name: 'Start voice session' }))
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'End session' })).toBeInTheDocument()
    })
    const stopped = vi.spyOn(port, 'voiceStop').mockResolvedValue(closure as unknown as VoiceClosure)

    await person.click(screen.getByRole('button', { name: 'End session' }))

    if (notice === 'none') {
      await waitFor(() => {
        expect(stopped).toHaveBeenCalled()
      })
      // The answer has been taken when the screen has settled after the call returned.
      await act(async () => {})
      expect(screen.queryByText(/its grant withdrawn/)).not.toBeInTheDocument()
      expect(screen.queryByText(/cannot confirm/)).not.toBeInTheDocument()
      expect(screen.queryByText(/has not yet confirmed/)).not.toBeInTheDocument()
    } else {
      await waitFor(() => {
        expect(screen.getByText(/its grant withdrawn/)).toBeInTheDocument()
      })
      const said = notice === 'pending' ? /still run in Session 1\./ : /cannot confirm that nothing/
      expect(screen.getByText(said)).toBeInTheDocument()
    }
  })

  // Section 9: a fence status this build does not know is not a fence the host did not owe. The
  // screen says it cannot confirm the host's workers, as it does for a status it could not read.
  it('says it cannot confirm the host\'s workers for a fence status it does not know', async () => {
    const person = userEvent.setup()
    const { port } = start()
    await waitForChoice()
    await person.click(screen.getByRole('button', { name: 'Start voice session' }))
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'End session' })).toBeInTheDocument()
    })
    const unknown = { closed_locally: false, fence: { kind: 'a_status_a_later_build_adds' }, host_failure: null }
    vi.spyOn(port, 'voiceStop').mockResolvedValue(unknown as unknown as VoiceClosure)

    await person.click(screen.getByRole('button', { name: 'End session' }))

    await waitFor(() => {
      expect(screen.getByText(/cannot confirm that nothing/)).toBeInTheDocument()
    })
  })

  // Section 9: a host that says it owed no fence leaves nothing to confirm, and the screen adds no
  // notice to a call that has ended.
  it('adds no notice when the host owed no fence', async () => {
    const person = userEvent.setup()
    start()
    await waitForChoice()
    await person.click(screen.getByRole('button', { name: 'Start voice session' }))
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'End session' })).toBeInTheDocument()
    })

    expect(screen.getByRole('heading', { name: 'Voice session' })).toBeInTheDocument()
    await person.click(screen.getByRole('button', { name: 'End session' }))

    await waitFor(() => {
      expect(screen.queryByRole('heading', { name: 'Voice session' })).not.toBeInTheDocument()
    })
    expect(screen.queryByText(/its grant withdrawn/)).not.toBeInTheDocument()
    expect(screen.queryByText(/cannot confirm/)).not.toBeInTheDocument()
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
      expect(screen.getByText(/did not confirm that it withdrew the grant/)).toBeInTheDocument()
    })
    expect(screen.queryByRole('heading', { name: 'Voice session' })).not.toBeInTheDocument()
    // The host's words and never the protocol code the client library puts before them. The call is
    // closed and there is nothing here to try again, so no action is said after them.
    const said = screen.getByText(/did not confirm that it withdrew the grant/).textContent ?? ''
    expect(said.endsWith('withdrew the grant: This host cannot be contacted right now.')).toBe(true)
    expect(said).not.toContain('RESOURCE_UNAVAILABLE')
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

  // The call is the application's own: a screen that is loaded again finds it where it is kept.
  it('takes up a call that is running when the screen is shown', async () => {
    start((controls) => {
      controls.holdAVoiceCall()
    })

    await screen.findByRole('heading', { name: 'Voice session' })
    expect(screen.getByText('Microphone on')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'End session' })).toBeEnabled()
    expect(screen.queryByRole('button', { name: 'Start voice session' })).not.toBeInTheDocument()
  })

  // The same call ends with the person's hang-up, on the voice session it names.
  it('ends a call it took up', async () => {
    const person = userEvent.setup()
    const { port } = start((controls) => {
      controls.holdAVoiceCall()
    })
    const stopped = vi.spyOn(port, 'voiceStop')
    await person.click(await screen.findByRole('button', { name: 'End session' }))

    await waitFor(() => {
      expect(screen.queryByRole('heading', { name: 'Voice session' })).not.toBeInTheDocument()
    })
    expect(stopped).toHaveBeenCalledTimes(1)
  })

  // A call that ends while the screen is open (the notification's stop, a failed connection, the
  // voice service closing it) is over on the screen, and the device's words say how it ended.
  it('says how a call that ended while the screen was open ended', async () => {
    const { controls } = start()
    await waitForChoice()
    await userEvent.setup().click(screen.getByRole('button', { name: 'Start voice session' }))
    await screen.findByRole('button', { name: 'End session' })

    controls.endVoiceCall({
      words: 'The call ended on this device: from its notification.',
      host: { kind: 'not_told', words: 'The host could not be reached.' }
    })

    await waitFor(() => {
      expect(screen.queryByRole('heading', { name: 'Voice session' })).not.toBeInTheDocument()
    })
    expect(screen.getByText(/from its notification/)).toBeInTheDocument()
    expect(screen.getByText(/did not confirm that it withdrew the call's grant: The host could not be reached\./)).toBeInTheDocument()
  })

  // The device is busy making a call that has no descriptor yet: a screen loaded again finds that,
  // offers no second start, and can end what the device is making without naming it.
  it('finds a device that is setting a call up and ends it without naming it', async () => {
    const person = userEvent.setup()
    const { controls, port } = start((controls) => {
      controls.settingUpAVoiceCall()
    })
    const stopped = vi.spyOn(port, 'voiceStop')

    const end = await screen.findByRole('button', { name: 'End the call' })
    expect(screen.queryByRole('button', { name: 'Start voice session' })).not.toBeInTheDocument()
    // Before a call runs the device cannot say what its microphone is doing, so the screen does
    // not say that nothing is listening.
    expect(screen.queryByText(/Nothing is listening/)).not.toBeInTheDocument()
    await person.click(end)

    // The stop is answered at once, and the device is still busy with what the host may have
    // made: the screen says it is ending, offers neither a start nor a second end, and goes on
    // reading until the device says it is done.
    expect(stopped).toHaveBeenCalledWith(null, {})
    const ending = await screen.findByRole('heading', { name: 'Ending a voice session' })
    expect(screen.queryByRole('button', { name: 'End the call' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Start voice session' })).not.toBeInTheDocument()
    // The control that was pressed is gone, and focus goes to the words that say what follows.
    expect(ending).toHaveFocus()
    // The call is not said to be closed: the device is still asking the host, and says so itself.
    expect(screen.queryByText(/This device's call is closed/)).not.toBeInTheDocument()

    controls.endVoiceCall({
      cause: 'requested',
      words: 'You ended the call.',
      host: { kind: 'not_told', words: 'The host never said whether it created the call.' }
    })

    await waitForChoice()
    expect(screen.getByText(/did not confirm that it withdrew the call's grant/)).toBeInTheDocument()
    // The control that was pressed is gone, and focus goes to what replaced it.
    expect(screen.getByRole('heading', { name: 'Start a voice session' })).toHaveFocus()
  })

  // A setup the screen watched is over when the device says so, in the device's words.
  it('says how a call that was being set up ended', async () => {
    const { controls } = start((controls) => {
      controls.settingUpAVoiceCall()
    })
    await screen.findByRole('button', { name: 'End the call' })

    controls.endVoiceCall({
      cause: 'start_unknown',
      words: 'The host never said whether it created the call. Nothing is running on this device.',
      host: { kind: 'not_told', words: 'The host never said whether it created the call.' }
    })

    await waitForChoice()
    expect(screen.getByText(/Nothing is running on this device/)).toBeInTheDocument()
  })

  it('takes up a call that was being set up once it runs', async () => {
    const { controls } = start((controls) => {
      controls.settingUpAVoiceCall()
    })
    await screen.findByRole('button', { name: 'End the call' })

    controls.holdAVoiceCall()

    await screen.findByRole('heading', { name: 'Voice session' })
    expect(screen.getByRole('button', { name: 'End session' })).toBeEnabled()
  })

  // What an end left owed is only known from a read of the device, and a read that fails is asked
  // again: the person is told that a grant may still be open as soon as the device says so.
  it('keeps asking the device what an end left until it answers', async () => {
    const person = userEvent.setup()
    const { controls, port } = start()
    await waitForChoice()
    await person.click(screen.getByRole('button', { name: 'Start voice session' }))
    await screen.findByRole('button', { name: 'End session' })
    controls.setConnected(false)
    const real = port.voiceCallState.bind(port)
    const stop = port.voiceStop.bind(port)
    let stopped = false
    let failed = false
    vi.spyOn(port, 'voiceStop').mockImplementation(async (...asked) => {
      const answer = await stop(...asked)
      stopped = true
      return answer
    })
    vi.spyOn(port, 'voiceCallState').mockImplementation(() => {
      if (stopped && !failed) {
        failed = true
        return Promise.reject(new Error('the device did not answer'))
      }
      return real()
    })

    await person.click(screen.getByRole('button', { name: 'End session' }))

    expect(
      await screen.findByText(/may still hold a grant for this call open/, {}, { timeout: 6000 })
    ).toBeInTheDocument()
    expect(failed).toBe(true)
  })

  // The device reads as busy while it finishes the end of a call this screen holds. The screen's
  // own hang-up says its own words, and the read in between does not turn the call into a setup.
  it('does not show the setup screen for the end of the call it holds', async () => {
    const person = userEvent.setup()
    const { controls, port } = start((controls) => {
      controls.holdAVoiceCall()
    })
    const real = port.voiceCallState.bind(port)
    let finish: (closure: VoiceClosure) => void = () => undefined
    vi.spyOn(port, 'voiceStop').mockImplementation(
      () =>
        new Promise<VoiceClosure>((resolve) => {
          finish = resolve
        })
    )
    const reading = vi.spyOn(port, 'voiceCallState').mockImplementation(async () => ({
      ...(await real()),
      running: false,
      setting_up: true,
      ending: true
    }))
    await person.click(await screen.findByRole('button', { name: 'End session' }))
    const before = reading.mock.calls.length

    await waitFor(() => {
      expect(reading.mock.calls.length).toBeGreaterThan(before)
    })

    expect(screen.queryByRole('heading', { name: 'Ending a voice session' })).not.toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Voice session' })).toBeInTheDocument()
    reading.mockRestore()
    // The device finishes the end it was asked for, and then says the call is over.
    controls.endVoiceCall({ cause: 'requested', words: 'You ended the call.' })
    await act(async () => {
      finish({ closed_locally: true, fence: { kind: 'not_owed' }, host_failure: null })
      await Promise.resolve()
    })
    await waitForChoice()
    expect(screen.queryByRole('heading', { name: 'Ending a voice session' })).not.toBeInTheDocument()
  })

  // The screen's own start tells its own answer. A read of the device while that start waits, which
  // sees the device busy with that very start, does not put the setup screen in the start's place.
  it('does not replace its own start with the setup screen', async () => {
    const person = userEvent.setup()
    // A call that ended still has the voice service to answer, so the screen reads the device.
    const { port } = start((controls) => {
      controls.holdAVoiceCall()
      controls.endVoiceCall({ broker: 'pending' })
    })
    await waitForChoice()
    const real = port.voiceCallState.bind(port)
    const reading = vi.spyOn(port, 'voiceCallState').mockImplementation(async () => ({
      ...(await real()),
      setting_up: true
    }))
    vi.spyOn(port, 'voiceStart').mockImplementation(() => new Promise(() => undefined))
    const before = reading.mock.calls.length

    await person.click(screen.getByRole('button', { name: 'Start voice session' }))
    await waitFor(() => {
      expect(reading.mock.calls.length).toBeGreaterThan(before + 1)
    })

    expect(screen.queryByRole('heading', { name: 'Starting a voice session' })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Starting…' })).toBeInTheDocument()
  })

  // The screen's own start waits for the host for as long as the host takes. The person can give it
  // up from the same screen: the stop names nothing, is answered at once, and the control says it is
  // ending until the start is over. The choice is theirs again when the host has answered.
  it('ends its own start while the host has not answered', async () => {
    const person = userEvent.setup()
    const { controls, port } = start()
    await waitForChoice()
    const answer = controls.holdVoiceStart()
    const stopped = vi.spyOn(port, 'voiceStop')

    await person.click(screen.getByRole('button', { name: 'Start voice session' }))
    const end = await screen.findByRole('button', { name: 'End the call' })
    expect(screen.getByRole('button', { name: 'Starting…' })).toBeDisabled()
    await person.click(end)

    expect(stopped).toHaveBeenCalledWith(null, {})
    expect(await screen.findByRole('button', { name: 'Ending…' })).toBeDisabled()
    expect(screen.queryByRole('button', { name: 'End the call' })).not.toBeInTheDocument()
    // Focus is on the words that say the end has begun, not on a control that is disabled and then
    // gone, and it stays there.
    const said = screen.getByText(/is ending its call/)
    expect(said).toHaveFocus()

    answer()

    const again = await screen.findByRole('button', { name: 'Start voice session' })
    expect(again).toBeEnabled()
    expect(screen.queryByRole('button', { name: 'Ending…' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'End the call' })).not.toBeInTheDocument()
    expect(screen.getByText(/given up before it began/)).toBeInTheDocument()
    // The words that had focus are gone with the start, and focus is on the control that starts
    // again, not on the page.
    expect(again).toHaveFocus()
  })

  // The end is offered while the start waits for the host and no longer: once the host has answered
  // there is nothing to give up, and the device holds no call to end while the screen reads what a
  // call would be again.
  it('takes the end away once the host has answered, before the preparation is read again', async () => {
    const person = userEvent.setup()
    const { controls, port } = start()
    await waitForChoice()
    controls.changeVoiceScope()
    const answer = controls.holdVoiceStart()
    // The second reading of what a call would be waits for the test, at the list of sessions it asks
    // for after the host has answered its preparation.
    const real = port.sessionList.bind(port)
    let release: () => void = () => undefined
    const gate = new Promise<void>((resolve) => {
      release = resolve
    })
    vi.spyOn(port, 'sessionList').mockImplementation(async (...asked) => {
      await gate
      return real(...asked)
    })

    await person.click(screen.getByRole('button', { name: 'Start voice session' }))
    await screen.findByRole('button', { name: 'End the call' })
    answer()

    await waitFor(() => {
      expect(screen.queryByRole('button', { name: 'End the call' })).not.toBeInTheDocument()
    })
    expect(screen.getByRole('button', { name: 'Starting…' })).toBeDisabled()
    release()
    expect(await screen.findByRole('button', { name: 'Start voice session' })).toBeEnabled()
  })

  // A stop the device refuses did nothing, so the control comes back and the device's words say why:
  // another press can do no harm, and it is the way out when a stop did not arrive.
  it('brings the end back, with the device’s words, when the device refuses it', async () => {
    const person = userEvent.setup()
    const { controls, port } = start()
    await waitForChoice()
    const answer = controls.holdVoiceStart()
    await person.click(screen.getByRole('button', { name: 'Start voice session' }))
    const end = await screen.findByRole('button', { name: 'End the call' })
    // The device is already ending what it was making, so it refuses a second stop.
    await port.voiceStop(null, {})

    await person.click(end)

    expect(await screen.findByText(/already ending its call/)).toBeInTheDocument()
    const back = await screen.findByRole('button', { name: 'End the call' })
    expect(back).toBeEnabled()
    // Focus went to the words that said the end had begun, and goes back to the control that is back.
    expect(back).toHaveFocus()

    // The host answers: the control goes while it holds focus, and focus goes to the start control.
    answer()
    const again = await screen.findByRole('button', { name: 'Start voice session' })
    await waitFor(() => {
      expect(again).toHaveFocus()
    })
  })

  // A start that was not given up is the same start it always was: the end control goes with the
  // start control when the call runs.
  it('takes the end away when the start it belongs to runs a call', async () => {
    const person = userEvent.setup()
    const { controls } = start()
    await waitForChoice()
    const answer = controls.holdVoiceStart()

    await person.click(screen.getByRole('button', { name: 'Start voice session' }))
    await screen.findByRole('button', { name: 'End the call' })
    answer()

    await screen.findByRole('button', { name: 'End session' })
    expect(screen.queryByRole('button', { name: 'End the call' })).not.toBeInTheDocument()
  })

  // A read that fails when what is owed lapses is asked again, so the warning does not outlive it.
  it('asks again when the read at the lapse of what is owed fails', async () => {
    const { port } = start((controls) => {
      controls.oweVoice({ until_ms: Date.now() + 400 })
    })
    await waitForChoice()
    expect(await screen.findByRole('status', { name: 'The last call' })).toBeInTheDocument()
    const real = port.voiceCallState.bind(port)
    let failed = false
    vi.spyOn(port, 'voiceCallState').mockImplementation(() => {
      if (!failed) {
        failed = true
        return Promise.reject(new Error('the device did not answer'))
      }
      return real()
    })

    await waitFor(
      () => {
        expect(screen.queryByRole('status', { name: 'The last call' })).not.toBeInTheDocument()
      },
      { timeout: 6000 }
    )
    expect(failed).toBe(true)
  })

  // A host that is reached again settles what it was owed, while no call runs and nothing on the
  // screen has changed: the screen reads again while a revocation is owed, and stops saying it.
  it('stops saying what is owed once the device has settled it with the host', async () => {
    const { controls } = start((controls) => {
      controls.oweVoice({})
    })
    await waitForChoice()
    expect(await screen.findByRole('status', { name: 'The last call' })).toBeInTheDocument()

    controls.settleOwedVoice()

    await waitFor(
      () => {
        expect(screen.queryByRole('status', { name: 'The last call' })).not.toBeInTheDocument()
      },
      { timeout: 8000 }
    )
  })

  // What the device owes stops being said when it lapses, with no other change on the screen.
  it('stops saying what is owed when it has lapsed', async () => {
    start((controls) => {
      controls.oweVoice({ until_ms: Date.now() + 400 })
    })
    await waitForChoice()
    expect(await screen.findByRole('status', { name: 'The last call' })).toBeInTheDocument()

    await waitFor(() => {
      expect(screen.queryByRole('status', { name: 'The last call' })).not.toBeInTheDocument()
    })
  })

  // The voice service is asked after the host and the screen does not wait for it: what it came to
  // is said when it is known.
  it('says what the voice service came to once it has said', async () => {
    const { controls } = start()
    await waitForChoice()
    await userEvent.setup().click(screen.getByRole('button', { name: 'Start voice session' }))
    await screen.findByRole('button', { name: 'End session' })
    controls.endVoiceCall({ broker: 'pending' })
    await waitForChoice()
    expect(screen.queryByText(/has not confirmed that it closed the call/)).not.toBeInTheDocument()

    controls.settleVoiceBroker('not_confirmed')

    await waitFor(() => {
      expect(screen.getByText(/has not confirmed that it closed the call/)).toBeInTheDocument()
    })
  })

  // The microphone is the first thing to say: a stop whose media this device could not confirm
  // stopped is not reported as a call that is closed, and the call stays on the screen.
  it('does not say the call is closed when this device could not confirm the media stopped', async () => {
    const person = userEvent.setup()
    const { port } = start((controls) => {
      controls.holdAVoiceCall()
    })
    vi.spyOn(port, 'voiceStop').mockResolvedValue({
      closed_locally: false,
      fence: null,
      host_failure: null
    })

    await person.click(await screen.findByRole('button', { name: 'End session' }))

    await waitFor(() => {
      expect(screen.getByText(/could not confirm that the call's microphone stopped/)).toBeInTheDocument()
    })
    expect(screen.queryByText(/This device's call is closed/)).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'End session' })).toBeInTheDocument()
  })

  // The delegations the voice announced are rows the device keeps, and this version did nothing
  // about any of them: the row says so, and whether the voice was told.
  it('shows each delegation as not done', async () => {
    const { controls } = start()
    await waitForChoice()
    await userEvent.setup().click(screen.getByRole('button', { name: 'Start voice session' }))
    await waitFor(() => {
      expect(screen.getByText('Nothing yet.')).toBeInTheDocument()
    })

    controls.announceVoiceDelegation('item_a1')

    await waitFor(() => {
      expect(screen.getByText('Not done. The voice was told so.')).toBeInTheDocument()
    })
    expect(screen.getByText('Asked 1.0 seconds in')).toBeInTheDocument()
    expect(screen.queryByText('Nothing yet.')).not.toBeInTheDocument()
    const panel = screen.getByRole('region', { name: 'Delegations' })
    expect(
      within(panel).getByText('Not done: this version does not act on spoken requests.')
    ).toBeInTheDocument()
    // Nothing was sent to the host: this screen has no way to submit a delegation.
    expect('voiceDelegate' in controls).toBe(false)
  })

  // The host the call belongs to can be lost while the application's own connection is fine, and
  // the call says so: the host requests go, and the local controls stay.
  it('takes the host requests away when the call itself has lost its host', async () => {
    const { controls } = start()
    await waitForChoice()
    await userEvent.setup().click(screen.getByRole('button', { name: 'Start voice session' }))
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Show what the host selected' })).toBeEnabled()
    })

    controls.setVoiceHost('lost')

    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Show what the host selected' })).toBeDisabled()
    })
    expect(screen.getByRole('button', { name: 'Mute microphone' })).toBeEnabled()
    expect(screen.getByRole('button', { name: 'End session' })).toBeEnabled()
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
          reason: 'this host cannot be contacted right now',
          rights: null,
          paired: false
        })
    })
    await startCall()

    await waitFor(() => {
      expect(askHost()).toBeDisabled()
    })
    expect(screen.getByText(OUT_OF_REACH)).toBeInTheDocument()
  })
})
