/**
 * What voice may do, for a person who already allowed it: the entry on the idle voice screen that
 * adds a close, after a confirmation on the unlocked screen, to what a call may ask the host for.
 *
 * It reads the standing grant from the host's preparation, offers the one action a person may add
 * in the protocol's own sentence, and allowing replaces the grant through the route to the host,
 * whose answer says what it could not carry and which workers have still to confirm the fence the
 * replacement owed. It is offered only while a spoken request can reach the host at all.
 */

import { act, cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { AppProvider } from '../../src/app/state'
import { fakeHost, type FakeHostControls } from '../../src/host/fake'
import type { HostPort } from '../../src/host/port'
import { VoiceGrantEntry } from '../../src/voice/VoiceGrantEntry'
import { VoiceRoute } from '../../src/voice/VoiceRoute'

afterEach(() => {
  cleanup()
})

const SESSION_MAIN = '8a7b6c50-22bb-4c3d-8e4f-000000000101'

const CLOSE_SENTENCE = 'Close a session, after a confirmation on an unlocked screen.'

/** Two of the sentences the screen lists for what the default grant permits. */
const NAVIGATE_SENTENCE = 'Move between the sessions this grant covers.'
const STATUS_SENTENCE = 'Read what a session is doing.'

/** The environment of a host other than the one the fake host starts as. */
const OTHER_HOST = '3f1a2c40-11aa-4b2c-9d3e-000000000002'

function start(setup?: (controls: FakeHostControls) => void): {
  controls: FakeHostControls
  port: HostPort
  settled: () => Promise<void>
} {
  const { port, controls } = fakeHost()
  setup?.(controls)
  // Every answer the host is waited for, so that a case can wait until what was asked has been
  // answered and read, whatever it was.
  const reads: Promise<unknown>[] = []
  const watched: HostPort = new Proxy(port, {
    get(target, name) {
      const member = Reflect.get(target, name) as unknown
      if (typeof member !== 'function') return member
      return (...args: unknown[]) => {
        const answer = (member as (...given: unknown[]) => unknown).apply(target, args)
        if (answer instanceof Promise) reads.push(answer)
        return answer
      }
    }
  })
  render(
    <AppProvider port={watched}>
      <VoiceRoute surface="ios" />
    </AppProvider>
  )
  const settled = async () => {
    // Until no further question is asked of the host once the answers so far are read.
    for (let seen = -1; seen !== reads.length; ) {
      seen = reads.length
      await act(async () => {
        await Promise.allSettled(reads)
      })
    }
  }
  return { controls, port, settled }
}

/** What a replacement asks for, in the order the actions are sorted. */
function asked(request: { readonly actions: readonly string[] | null }): readonly string[] {
  return [...(request.actions ?? [])].sort()
}

describe('what voice may do', () => {
  // A person is not asked to allow what cannot happen: with the constant off, which every shipped
  // build holds, the idle screen offers nothing to add.
  it('is not offered while no spoken request reaches the host', async () => {
    const { settled } = start()
    expect(await screen.findByRole('button', { name: 'Start voice session' })).toBeInTheDocument()
    // Nothing is offered only once the host has answered what could be added: asserting before the
    // answer is read would pass for any screen.
    await settled()
    expect(screen.queryByTestId('voice-grant-entry')).toBeNull()
    expect(screen.queryByText(CLOSE_SENTENCE)).toBeNull()
  })

  // KR-REQ-15.13: the close is offered in the protocol's sentence, off, and the standing grant is
  // what the boxes show; allowing sends the call's sessions and the default actions with the close
  // as a replacement grant, and the screen then reads what the host says the grant permits.
  it('offers a close, off, and allowing replaces the grant with the defaults and the close', async () => {
    const { controls } = start((fake) => {
      fake.speechReachesTheHost(true)
    })
    const entry = await screen.findByTestId('voice-grant-entry')
    expect(within(entry).getByRole('heading', { name: 'What voice may do' })).toBeInTheDocument()
    const close = within(entry).getByRole('checkbox', { name: new RegExp(CLOSE_SENTENCE) })
    expect(close).not.toBeChecked()
    expect(within(entry).getByTestId('voice-grant-entry-allow')).toBeDisabled()

    await userEvent.click(close)
    await userEvent.click(within(entry).getByTestId('voice-grant-entry-allow'))

    await waitFor(() => {
      expect(controls.voiceAllows).toHaveLength(1)
    })
    expect(controls.voiceAllows[0]).toMatchObject({ sessionIds: [SESSION_MAIN] })
    expect(asked(controls.voiceAllows[0])).toEqual(
      ['navigate', 'status', 'brief', 'compose_prompt', 'close_session'].sort()
    )
    expect(await screen.findByTestId('voice-grant-entry-result')).toHaveTextContent('Allowed.')
    // What a call would be is read again: the close is now among what the grant permits, which the
    // list of what speaking will be allowed to do says in the host's sentence, and the box shows it.
    await waitFor(() => {
      expect(
        within(screen.getByTestId('voice-grant-entry')).getByRole('checkbox', {
          name: new RegExp(CLOSE_SENTENCE)
        })
      ).toBeChecked()
    })
    expect(screen.getByText(CLOSE_SENTENCE)).toBeInTheDocument()
  })

  // The grant is read, not assumed: one that already permits a close shows it on, and taking it
  // off sends the defaults alone.
  it('shows a close the grant already permits, and taking it off allows the defaults alone', async () => {
    const { controls } = start((fake) => {
      fake.speechReachesTheHost(true)
    })
    const entry = await screen.findByTestId('voice-grant-entry')
    await userEvent.click(within(entry).getByRole('checkbox', { name: new RegExp(CLOSE_SENTENCE) }))
    await userEvent.click(within(entry).getByTestId('voice-grant-entry-allow'))
    await screen.findByTestId('voice-grant-entry-result')

    const boxes = () =>
      within(screen.getByTestId('voice-grant-entry')).getByRole('checkbox', {
        name: new RegExp(CLOSE_SENTENCE)
      })
    await waitFor(() => {
      expect(boxes()).toBeChecked()
    })
    await userEvent.click(boxes())
    await userEvent.click(within(screen.getByTestId('voice-grant-entry')).getByTestId('voice-grant-entry-allow'))

    await waitFor(() => {
      expect(controls.voiceAllows).toHaveLength(2)
    })
    expect(asked(controls.voiceAllows[1])).toEqual(['navigate', 'status', 'brief', 'compose_prompt'].sort())
  })

  // The entry changes the one action the person ticks, and nothing the host's grant says besides:
  // a grant that permits only a close, with that box cleared, adds none of the defaults.
  it('adds nothing to a grant that permits only a close when the close is cleared', async () => {
    const { controls } = start((fake) => {
      fake.speechReachesTheHost(true)
      fake.standingVoiceGrant(['close_session'])
    })
    const entry = await screen.findByTestId('voice-grant-entry')
    const close = within(entry).getByRole('checkbox', { name: new RegExp(CLOSE_SENTENCE) })
    expect(close).toBeChecked()

    await userEvent.click(close)
    await userEvent.click(within(entry).getByTestId('voice-grant-entry-allow'))

    await waitFor(() => {
      expect(controls.voiceAllows).toHaveLength(1)
    })
    expect(asked(controls.voiceAllows[0])).toEqual([])
  })

  // A grant that permits more than the defaults keeps what it permits: only the close changes.
  it('keeps every other action of a broader grant when the close is added', async () => {
    const { controls } = start((fake) => {
      fake.speechReachesTheHost(true)
      fake.standingVoiceGrant(['navigate', 'submit_prompt', 'answer_approval'])
    })
    const entry = await screen.findByTestId('voice-grant-entry')

    await userEvent.click(within(entry).getByRole('checkbox', { name: new RegExp(CLOSE_SENTENCE) }))
    await userEvent.click(within(entry).getByTestId('voice-grant-entry-allow'))

    await waitFor(() => {
      expect(controls.voiceAllows).toHaveLength(1)
    })
    expect(asked(controls.voiceAllows[0])).toEqual(
      ['answer_approval', 'close_session', 'navigate', 'submit_prompt'].sort()
    )
  })

  // The grant's own sessions are kept, whichever session the screen was opened for: a grant over
  // two sessions, with the screen opened for one, still covers both.
  it('keeps the sessions the grant covers when the screen was opened for one of them', async () => {
    const other = '8a7b6c50-22bb-4c3d-8e4f-000000000102'
    window.history.pushState({}, '', `/?session=${SESSION_MAIN}`)
    try {
      const { controls } = start((fake) => {
        fake.speechReachesTheHost(true)
        fake.standingVoiceGrant(['navigate', 'status'], [SESSION_MAIN, other])
      })
      const entry = await screen.findByTestId('voice-grant-entry')

      await userEvent.click(within(entry).getByRole('checkbox', { name: new RegExp(CLOSE_SENTENCE) }))
      await userEvent.click(within(entry).getByTestId('voice-grant-entry-allow'))

      await waitFor(() => {
        expect(controls.voiceAllows).toHaveLength(1)
      })
      expect([...controls.voiceAllows[0].sessionIds].sort()).toEqual([SESSION_MAIN, other].sort())
    } finally {
      window.history.pushState({}, '', '/')
    }
  })

  // What is shown is bound to the host it was read from: when the host is another by the time the
  // person presses, nothing is sent, and the screen above the entry is read again with it.
  it('sends nothing when the host changed between what was shown and the press', async () => {
    const { port, controls } = fakeHost()
    controls.speechReachesTheHost(true)
    const onChanged = vi.fn(() => Promise.resolve(true))
    render(<VoiceGrantEntry port={port} sessionNames={{}} onChanged={onChanged} />)
    const entry = await screen.findByTestId('voice-grant-entry')
    await userEvent.click(within(entry).getByRole('checkbox', { name: new RegExp(CLOSE_SENTENCE) }))

    act(() => {
      controls.switchHost(OTHER_HOST)
    })
    await userEvent.click(within(entry).getByTestId('voice-grant-entry-allow'))

    expect((await screen.findByTestId('voice-grant-entry-failure')).textContent).toContain('has changed')
    expect(controls.voiceAllows).toHaveLength(0)
    expect(onChanged).toHaveBeenCalledTimes(1)
  })

  // The grant changing under the screen is the same: what was shown is not what is changed, and
  // the list of what speaking will be allowed to do, above the entry, is read again with it.
  it('sends nothing when the grant changed between what was shown and the press, and shows the new grant above', async () => {
    const { controls, settled } = start((fake) => {
      fake.speechReachesTheHost(true)
    })
    const entry = await screen.findByTestId('voice-grant-entry')
    expect(screen.getByText(STATUS_SENTENCE)).toBeInTheDocument()
    await userEvent.click(within(entry).getByRole('checkbox', { name: new RegExp(CLOSE_SENTENCE) }))
    await settled()

    controls.standingVoiceGrant(['navigate'])
    await userEvent.click(within(screen.getByTestId('voice-grant-entry')).getByTestId('voice-grant-entry-allow'))

    expect((await screen.findByTestId('voice-grant-entry-failure')).textContent).toContain('has changed')
    expect(controls.voiceAllows).toHaveLength(0)
    await waitFor(() => {
      expect(screen.queryByText(STATUS_SENTENCE)).toBeNull()
    })
    expect(screen.getByText(NAVIGATE_SENTENCE)).toBeInTheDocument()
  })

  // What was read from one host is not shown for the next: when the connection moves to another
  // host, the entry and the list above it are gone until the host in use has been read, so that no
  // press can act on the one that was left; a change is then sent to the host in use.
  it('clears what it read when the connection moves to another host, and reads the new one', async () => {
    const { controls, settled } = start((fake) => {
      fake.speechReachesTheHost(true)
    })
    await screen.findByTestId('voice-grant-entry')
    expect(screen.getByText(STATUS_SENTENCE)).toBeInTheDocument()
    await settled()

    const held = controls.hold('voicePrepare')
    controls.standingVoiceGrant(['navigate'])
    act(() => {
      controls.switchHost(OTHER_HOST)
    })

    await waitFor(() => {
      expect(screen.queryByTestId('voice-grant-entry')).toBeNull()
    })
    expect(screen.queryByText(STATUS_SENTENCE)).toBeNull()
    expect(screen.queryByText(NAVIGATE_SENTENCE)).toBeNull()

    await act(async () => {
      held.release()
      await Promise.resolve()
    })
    const entry = await screen.findByTestId('voice-grant-entry')
    await waitFor(() => {
      expect(screen.getByText(NAVIGATE_SENTENCE)).toBeInTheDocument()
    })
    expect(screen.queryByText(STATUS_SENTENCE)).toBeNull()
    await userEvent.click(within(entry).getByRole('checkbox', { name: new RegExp(CLOSE_SENTENCE) }))
    await userEvent.click(within(entry).getByTestId('voice-grant-entry-allow'))
    await waitFor(() => {
      expect(controls.voiceAllows).toHaveLength(1)
    })
    expect(controls.voiceAllows[0].environmentId).toBe(OTHER_HOST)
  })

  // A read of what a call would be that was made for a host the connection has left is not shown,
  // even when the connection has come back to that host since: it would put the grant the host held
  // then above an entry that reads the grant it holds now.
  it('does not show a refresh made for a host the connection has left, even after it came back', async () => {
    const { controls, port, settled } = start((fake) => {
      fake.speechReachesTheHost(true)
    })
    const home = (await port.connectionState()).environment_id as string
    const entry = await screen.findByTestId('voice-grant-entry')
    await userEvent.click(within(entry).getByRole('checkbox', { name: new RegExp(CLOSE_SENTENCE) }))
    await settled()

    // The grant changes, and the press that finds it so has the screen read again, slowly.
    const held = controls.hold('voicePrepare')
    controls.standingVoiceGrant(['navigate'])
    await userEvent.click(within(entry).getByTestId('voice-grant-entry-allow'))
    await waitFor(() => {
      expect(held.count).toBe(1)
    })
    await act(async () => {
      held.answer(0)
      await Promise.resolve()
    })
    await waitFor(() => {
      expect(held.count).toBeGreaterThanOrEqual(3)
    })
    // The connection moves to another host and then back, and the grant is read once more.
    const reads = held.count
    act(() => {
      controls.switchHost(OTHER_HOST)
    })
    await waitFor(() => {
      expect(held.count).toBeGreaterThan(reads)
    })
    const readsMoved = held.count
    controls.standingVoiceGrant(['navigate', 'status'])
    act(() => {
      controls.switchHost(home)
    })
    await waitFor(() => {
      expect(held.count).toBeGreaterThan(readsMoved)
    })
    // The read made after the return is answered first, and the reads made before it after.
    await act(async () => {
      held.answer(held.count - 1)
      await Promise.resolve()
    })
    await act(async () => {
      held.release()
      await Promise.resolve()
    })

    await waitFor(() => {
      expect(screen.getByText(STATUS_SENTENCE)).toBeInTheDocument()
    })
    await settled()
    expect(screen.getByText(STATUS_SENTENCE)).toBeInTheDocument()
    expect(screen.getByText(NAVIGATE_SENTENCE)).toBeInTheDocument()
  })

  // Section 9: a replacement ends the calls under the grant it replaces, and a withdrawal is not
  // complete until its barrier holds: the sessions the host has still to confirm are named.
  it('says what the host could not carry and which sessions it has still to confirm', async () => {
    start((fake) => {
      fake.speechReachesTheHost(true)
      fake.holdBackOnNextVoiceAllow(['close_session'])
      fake.leaveNextVoiceChangePendingAt([SESSION_MAIN])
    })
    const entry = await screen.findByTestId('voice-grant-entry')
    await userEvent.click(within(entry).getByRole('checkbox', { name: new RegExp(CLOSE_SENTENCE) }))
    await userEvent.click(within(entry).getByTestId('voice-grant-entry-allow'))

    const result = await screen.findByTestId('voice-grant-entry-result')
    expect(result).toHaveTextContent('Allowed, except close session')
    expect(result).toHaveTextContent('have ended.')
    expect(result).toHaveTextContent('that nothing the calls sent can still run in Session 1.')
  })

  // An answer the host never confirmed is not a change: the person is told, and allowing it again
  // is what settles it.
  it('says so when the host did not confirm the change', async () => {
    const { controls } = start((fake) => {
      fake.speechReachesTheHost(true)
      fake.leaveNextVoiceAllowUnconfirmed()
    })
    const entry = await screen.findByTestId('voice-grant-entry')
    await userEvent.click(within(entry).getByRole('checkbox', { name: new RegExp(CLOSE_SENTENCE) }))
    await userEvent.click(within(entry).getByTestId('voice-grant-entry-allow'))

    expect((await screen.findByTestId('voice-grant-entry-failure')).textContent).toContain(
      'did not confirm'
    )
    await userEvent.click(within(entry).getByTestId('voice-grant-entry-allow'))
    expect(await screen.findByTestId('voice-grant-entry-result')).toHaveTextContent('Allowed.')
    expect(controls.voiceAllows).toHaveLength(2)
  })
})
