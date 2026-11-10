/**
 * What voice may do, for a person who already allowed it: the entry on the idle voice screen that
 * adds a close, after a confirmation on the unlocked screen, to what a call may ask the host for.
 *
 * It reads the standing grant from the host's preparation, offers the one action a person may add
 * in the protocol's own sentence, and allowing replaces the grant through the route to the host,
 * whose answer says what it could not carry and which workers have still to confirm the fence the
 * replacement owed. It is offered only while a spoken request can reach the host at all.
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

const SESSION_MAIN = '8a7b6c50-22bb-4c3d-8e4f-000000000101'

const CLOSE_SENTENCE = 'Close a session, after a confirmation on an unlocked screen.'

function start(setup?: (controls: FakeHostControls) => void): { controls: FakeHostControls } {
  const { port, controls } = fakeHost()
  setup?.(controls)
  render(
    <AppProvider port={port}>
      <VoiceRoute surface="ios" />
    </AppProvider>
  )
  return { controls }
}

describe('what voice may do', () => {
  // A person is not asked to allow what cannot happen: with the constant off, which every shipped
  // build holds, the idle screen offers nothing to add.
  it('is not offered while no spoken request reaches the host', async () => {
    start()
    expect(await screen.findByRole('button', { name: 'Start voice session' })).toBeInTheDocument()
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
    expect(controls.voiceAllows[0]).toEqual({
      sessionIds: [SESSION_MAIN],
      actions: ['navigate', 'status', 'brief', 'compose_prompt', 'close_session']
    })
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
    expect(controls.voiceAllows[1].actions).toEqual(['navigate', 'status', 'brief', 'compose_prompt'])
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
