/**
 * The first-use step of the voice screen: what allowing voice permits, and for which sessions.
 *
 * A host that holds no voice grant for this device refuses to say what a call would be, and the
 * screen turns that refusal into the question it is: it shows the host's words, every action the
 * grant permits in the sentence the protocol states it in, and the sessions to choose from. Nothing
 * is allowed until the person presses the control, and the preparation is asked again only when the
 * host has granted what was allowed.
 */

import { act, cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { AppProvider } from '../../src/app/state'
import { fakeHost, type FakeHostControls } from '../../src/host/fake'
import type { HostPort } from '../../src/host/port'
import { VoiceGrantStep } from '../../src/voice/VoiceGrantStep'
import { VoiceRoute } from '../../src/voice/VoiceRoute'

afterEach(() => {
  cleanup()
})

/** The session the fake host's workers answer for. */
const SESSION_MAIN = '8a7b6c50-22bb-4c3d-8e4f-000000000101'
const SESSION_BUILD = '8a7b6c50-22bb-4c3d-8e4f-000000000102'

/** The environment of a host other than the one the fake host starts as. */
const OTHER_HOST = '3f1a2c40-11aa-4b2c-9d3e-000000000002'

function start(setup?: (controls: FakeHostControls) => void): {
  controls: FakeHostControls
  port: HostPort
} {
  const { port, controls } = fakeHost()
  controls.requireVoiceGrant('PERMISSION_DENIED: name the sessions this voice session may reach')
  setup?.(controls)
  render(
    <AppProvider port={port}>
      <VoiceRoute surface="ios" />
    </AppProvider>
  )
  return { controls, port }
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
    const { controls, port } = start()
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
    // The allowance is for the host that listed the sessions, and says which it is.
    expect(asked.environmentId).toBe((await port.connectionState()).environment_id)
    expect(await screen.findByRole('button', { name: 'Start voice session' })).toBeInTheDocument()
  })

  // KR-REQ-15.21: what is granted is what was chosen when the person pressed the control: the
  // sessions cannot be changed while the host is answering, so the result never describes a
  // selection other than the one it was granted for.
  it('keeps the chosen sessions fixed while the host answers', async () => {
    const { controls } = start()
    const held = controls.hold('voiceAllow')
    await screen.findAllByRole('checkbox')
    await userEvent.click(screen.getByTestId('voice-allow'))
    await waitFor(() => {
      expect(held.count).toBe(1)
    })
    for (const box of screen.getAllByRole('checkbox')) expect(box).toBeDisabled()
    held.release()
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

  // KR-REQ-15.21: an action the grant could not carry is read before the call is shown. The person
  // goes on when they have read it, not before.
  it('says what the grant could not carry and waits for the person to go on', async () => {
    start((fake) => {
      fake.holdBackOnNextVoiceAllow(['compose_prompt'])
    })
    await screen.findAllByRole('checkbox')
    await userEvent.click(screen.getByTestId('voice-allow'))
    const result = await screen.findByTestId('voice-grant-result')
    expect(result).toHaveTextContent('Allowed, except compose prompt')
    expect(screen.queryByRole('button', { name: 'Start voice session' })).toBeNull()
    // What was granted is what is shown: the sessions can no longer be changed under the result,
    // and the way on has the focus.
    for (const box of screen.getAllByRole('checkbox')) expect(box).toBeDisabled()
    expect(screen.getByTestId('voice-grant-continue')).toHaveFocus()
    // The result is read with the control, not apart from it.
    expect(screen.getByTestId('voice-grant-continue')).toHaveAccessibleDescription(
      /Allowed, except compose prompt/
    )
    await userEvent.click(screen.getByTestId('voice-grant-continue'))
    expect(await screen.findByRole('button', { name: 'Start voice session' })).toBeInTheDocument()
  })

  // Section 9: a withdrawal is not complete until its barrier holds, so a replacement that ended a
  // call whose close could still reach a worker names the sessions the host has still to confirm,
  // and the person goes on when they have read it.
  it('names the sessions the host has still to confirm after replacing the allowance', async () => {
    const { controls } = start((fake) => {
      fake.leaveNextVoiceChangePendingAt([SESSION_MAIN])
    })
    await screen.findAllByRole('checkbox')
    await userEvent.click(screen.getByTestId('voice-allow'))
    const result = await screen.findByTestId('voice-grant-result')
    expect(result).toHaveTextContent('have ended.')
    expect(result).toHaveTextContent('that nothing the calls sent can still run in Session 1.')
    expect(result).not.toHaveTextContent('possibly others')
    expect(result).not.toHaveTextContent('except')
    expect(controls.voiceAllows).toHaveLength(1)
    expect(screen.queryByRole('button', { name: 'Start voice session' })).toBeNull()
    await userEvent.click(screen.getByTestId('voice-grant-continue'))
    expect(await screen.findByRole('button', { name: 'Start voice session' })).toBeInTheDocument()
  })

  // The host has replaced the grant by the time it answers. An answer with no fence status this
  // build can read is not "none owed": the person is told the app cannot confirm the host's workers
  // before they go on.
  it('says it cannot confirm the host\'s workers when the answer gave no readable status', async () => {
    start((fake) => {
      fake.leaveNextVoiceAllowFenceUnreadable()
    })
    await screen.findAllByRole('checkbox')
    await userEvent.click(screen.getByTestId('voice-allow'))
    const result = await screen.findByTestId('voice-grant-result')
    expect(result).toHaveTextContent('cannot confirm that nothing the call sent can still run')
    expect(screen.queryByRole('button', { name: 'Start voice session' })).toBeNull()
    await userEvent.click(screen.getByTestId('voice-grant-continue'))
    expect(await screen.findByRole('button', { name: 'Start voice session' })).toBeInTheDocument()
  })

  // What a grant permits is not what this version carries out, and the first question says so
  // beside the list of actions.
  it('says beside the actions that spoken requests are not acted on', async () => {
    start()
    await screen.findAllByRole('checkbox')
    expect(screen.getByTestId('voice-not-acted-on')).toHaveTextContent(
      'Not done: this version does not act on spoken requests.'
    )
  })

  // Section 9: the host keeps the workers that have not confirmed before any that have, but an answer
  // that left workers out may be missing some that have not, and the screen says so.
  it('says when the answer left workers out of the sessions to confirm', async () => {
    start((fake) => {
      fake.leaveNextVoiceChangePendingAt([SESSION_MAIN, SESSION_BUILD], 40)
    })
    await screen.findAllByRole('checkbox')
    await userEvent.click(screen.getByTestId('voice-allow'))
    const result = await screen.findByTestId('voice-grant-result')
    expect(result).toHaveTextContent('in Session 1, Session 2, and possibly others.')
  })

  // KR-REQ-15.21: an answer the host never confirmed does not move the person on as if voice were
  // allowed, and allowing it again is what settles it.
  it('stays on the question when the host did not confirm the grant', async () => {
    const { controls } = start((fake) => {
      fake.leaveNextVoiceAllowUnconfirmed()
    })
    await screen.findAllByRole('checkbox')
    await userEvent.click(screen.getByTestId('voice-allow'))
    expect((await screen.findByTestId('voice-grant-failure')).textContent).toContain(
      'did not confirm'
    )
    expect(screen.queryByRole('button', { name: 'Start voice session' })).toBeNull()
    await userEvent.click(screen.getByTestId('voice-allow'))
    expect(await screen.findByRole('button', { name: 'Start voice session' })).toBeInTheDocument()
    expect(controls.voiceAllows).toHaveLength(2)
  })

  // The sessions listed are the host's that listed them: when the connection moves to another host
  // while the step is open, allowing them is not sent over to it, whatever the screen around the
  // step does about the change.
  it('sends nothing when the host changed while the step was open', async () => {
    const { port, controls } = fakeHost()
    const onAllowed = vi.fn()
    render(<VoiceGrantStep port={port} refusal={null} named={[]} moves={() => 0} onAllowed={onAllowed} />)
    await screen.findAllByRole('checkbox')

    act(() => {
      controls.switchHost(OTHER_HOST)
    })
    await userEvent.click(screen.getByTestId('voice-allow'))

    expect((await screen.findByTestId('voice-grant-failure')).textContent).toContain('another host')
    expect(controls.voiceAllows).toHaveLength(0)
    expect(onAllowed).not.toHaveBeenCalled()
  })

  // On the voice screen the step is shown again for the host the connection moved to: the sessions
  // of the host that was left are gone, and what the new host lists is read before anything can be
  // allowed.
  it('is shown again for the new host when the connection moves while it is open', async () => {
    const { controls } = start()
    expect((await screen.findAllByRole('checkbox')).length).toBeGreaterThan(0)

    act(() => {
      controls.switchHost(OTHER_HOST)
    })

    expect(await screen.findByTestId('voice-no-sessions')).toBeInTheDocument()
    expect(screen.queryAllByRole('checkbox')).toHaveLength(0)
    expect(screen.getByTestId('voice-allow')).toBeDisabled()
    expect(controls.voiceAllows).toHaveLength(0)
  })

  // An allowing that was asked for on one host and answered after the connection moved to another is
  // nobody's: the screen asks the host in use about none of the sessions it was for.
  it('ignores the answer to an allowing made for a host the connection has since left', async () => {
    const { port, controls } = fakeHost()
    controls.requireVoiceGrant('PERMISSION_DENIED: name the sessions this voice session may reach')
    const asked: (readonly string[])[] = []
    const watched: HostPort = {
      ...port,
      voicePrepare: (params) => {
        asked.push((params as { readonly session_ids: readonly string[] }).session_ids)
        return port.voicePrepare(params)
      }
    }
    render(
      <AppProvider port={watched}>
        <VoiceRoute surface="ios" />
      </AppProvider>
    )
    await screen.findAllByRole('checkbox')
    const held = controls.hold('voiceAllow')
    await userEvent.click(screen.getByTestId('voice-allow'))
    await waitFor(() => {
      expect(held.count).toBe(1)
    })
    const before = asked.length
    act(() => {
      controls.switchHost(OTHER_HOST)
    })
    await waitFor(() => {
      expect(asked.length).toBeGreaterThan(before)
    })

    // The host the allowing was for answers it now.
    await act(async () => {
      held.release()
      await Promise.resolve()
    })

    expect(asked.at(-1)).toEqual([])
    expect(await screen.findByRole('button', { name: 'Start voice session' })).toBeInTheDocument()
  })

  // The step answers for itself only while it is shown, and says which count of moves the allowing
  // was submitted under, so the screen can tell it from one made for a host it has left.
  it('does not answer an allowing after it is gone', async () => {
    const { port, controls } = fakeHost()
    const onAllowed = vi.fn()
    const view = render(
      <VoiceGrantStep port={port} refusal={null} named={[]} moves={() => 0} onAllowed={onAllowed} />
    )
    await screen.findAllByRole('checkbox')
    const held = controls.hold('voiceAllow')
    await userEvent.click(screen.getByTestId('voice-allow'))
    await waitFor(() => {
      expect(held.count).toBe(1)
    })

    view.unmount()
    await act(async () => {
      held.release()
      await Promise.resolve()
    })

    expect(onAllowed).not.toHaveBeenCalled()
  })

  it('answers an allowing with the count of moves it was submitted under', async () => {
    const { port, controls } = fakeHost()
    const onAllowed = vi.fn()
    let moves = 0
    render(
      <VoiceGrantStep port={port} refusal={null} named={[]} moves={() => moves} onAllowed={onAllowed} />
    )
    await screen.findAllByRole('checkbox')
    const held = controls.hold('voiceAllow')
    await userEvent.click(screen.getByTestId('voice-allow'))
    await waitFor(() => {
      expect(held.count).toBe(1)
    })

    moves = 1
    await act(async () => {
      held.release()
      await Promise.resolve()
    })

    await waitFor(() => {
      expect(onAllowed).toHaveBeenCalledTimes(1)
    })
    expect(onAllowed).toHaveBeenCalledWith(expect.any(Array), 0)
  })

  // The session an address named is a session of the host it was opened for.
  it('drops the session the address named when the connection moves to another host', async () => {
    window.history.pushState({}, '', `/?session=${SESSION_MAIN}`)
    try {
      const { port, controls } = fakeHost()
      const asked: (readonly string[])[] = []
      const watched: HostPort = {
        ...port,
        voicePrepare: (params) => {
          asked.push((params as { readonly session_ids: readonly string[] }).session_ids)
          return port.voicePrepare(params)
        }
      }
      render(
        <AppProvider port={watched}>
          <VoiceRoute surface="ios" />
        </AppProvider>
      )
      expect(await screen.findByRole('button', { name: 'Start voice session' })).toBeInTheDocument()
      expect(asked.at(-1)).toEqual([SESSION_MAIN])

      const before = asked.length
      act(() => {
        controls.switchHost(OTHER_HOST)
      })
      await waitFor(() => {
        expect(asked.length).toBeGreaterThan(before)
      })

      expect(asked.at(-1)).toEqual([])
    } finally {
      window.history.pushState({}, '', '/')
    }
  })

  // A connection that drops while the sessions are read leaves the step saying so, and not that it
  // is still reading; the person reads them again.
  it('says the sessions could not be read, and reads them again', async () => {
    const { port } = fakeHost()
    let asked = 0
    const dropping: HostPort = {
      ...port,
      connectionState: async () => {
        asked += 1
        const state = await port.connectionState()
        // The connection is down when the list has been read, and up again by the next read.
        return asked === 2 ? { ...state, connected: false } : state
      }
    }
    render(
      <VoiceGrantStep port={dropping} refusal={null} named={[]} moves={() => 0} onAllowed={vi.fn()} />
    )

    expect(await screen.findByTestId('voice-sessions-failure')).toBeInTheDocument()
    expect(screen.queryByText(/Reading the host/)).toBeNull()
    expect(screen.getByTestId('voice-allow')).toBeDisabled()

    await userEvent.click(screen.getByTestId('voice-sessions-reread'))

    expect((await screen.findAllByRole('checkbox')).length).toBeGreaterThan(0)
    await waitFor(() => {
      expect(screen.getByTestId('voice-allow')).toBeEnabled()
    })
    expect(screen.queryByTestId('voice-sessions-failure')).toBeNull()
  })

  // The sessions the person allowed on one host are not asked about on the next: the voice screen
  // asks the host it was moved to about what it shows, and names none the person chose elsewhere.
  it('asks about none of the sessions allowed on a host the connection has left', async () => {
    const { port, controls } = fakeHost()
    controls.requireVoiceGrant('PERMISSION_DENIED: name the sessions this voice session may reach')
    const asked: (readonly string[])[] = []
    const watched: HostPort = {
      ...port,
      voicePrepare: (params) => {
        asked.push((params as { readonly session_ids: readonly string[] }).session_ids)
        return port.voicePrepare(params)
      }
    }
    render(
      <AppProvider port={watched}>
        <VoiceRoute surface="ios" />
      </AppProvider>
    )
    await screen.findAllByRole('checkbox')
    await userEvent.click(screen.getByTestId('voice-allow'))
    expect(await screen.findByRole('button', { name: 'Start voice session' })).toBeInTheDocument()
    expect(asked.at(-1)).not.toHaveLength(0)

    const before = asked.length
    act(() => {
      controls.switchHost(OTHER_HOST)
    })
    await waitFor(() => {
      expect(asked.length).toBeGreaterThan(before)
    })

    expect(asked.at(-1)).toEqual([])
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
