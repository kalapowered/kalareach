/**
 * A session screen on a phone opens its session, follows what the host says of it, and keeps
 * everything it asks tied to that opening (KR-REQ-19.08).
 *
 * The host is the fake one, which serves a call by the opening it names: a call under an opening
 * that was replaced is refused as native code refuses it, and one under an opening whose standing is
 * over is refused as the host does. So what these tests check is what the page does with the
 * answers, and that it names the right opening to begin with.
 */

import { type ReactNode } from 'react'
import { describe, expect, it } from 'vitest'
import { act, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { ActionRight, Receipt } from '@kalareach/protocol'

import { AppProvider, useApp } from '../../src/app/state'
import { fakeHost } from '../../src/host/fake'
import type { HostPort, SessionStanding } from '../../src/host/port'
import { MobileSession } from '../../src/mobile/views/MobileSession'
import { useLifecycle } from '../../src/mobile/useLifecycle'

const SESSION_MAIN = '8a7b6c50-22bb-4c3d-8e4f-000000000101'
const SHARE = '5d0e2a40-77aa-4b2c-9d3e-000000000901'

/** A standing the host reports for a share that holds exactly `actions`. */
function share(
  actions: readonly ActionRight[],
  more: Partial<Extract<SessionStanding, { state: 'open' }>> = {}
): SessionStanding {
  return {
    state: 'open',
    via: 'share',
    grant_id: SHARE,
    actions,
    includes_live_screen: true,
    history_from_ms: null,
    ends_at_ms: null,
    ...more
  }
}

/** What the passing messages say, so a test can see whether one was shown. */
function Said(): ReactNode {
  const { toast } = useApp()
  return <p data-testid="said">{toast?.text ?? ''}</p>
}

/** The session screen as the phone's shell renders it, under `grantId` when it names one. */
function OnSession({
  grantId = null,
  onBack = () => undefined
}: {
  readonly grantId?: string | null
  readonly onBack?: () => void
}): ReactNode {
  const lifecycle = useLifecycle(null)
  return (
    <MobileSession
      sessionId={SESSION_MAIN}
      grantId={grantId}
      surface="ios"
      lifecycle={lifecycle}
      connected={true}
      onBack={onBack}
    />
  )
}

function screenOn(port: HostPort, grantId: string | null = null, onBack?: () => void): ReactNode {
  return (
    <AppProvider port={port}>
      <OnSession grantId={grantId} onBack={onBack} />
      <Said />
    </AppProvider>
  )
}

/** The text of the conversation's first entry, which says the screen read it. */
const FIRST_ENTRY = 'Find why the reconnect test is flaky.'

describe('a session screen opens its session (KR-REQ-19.08)', () => {
  it('opens once under a token of its own, asks everything under it, and leaves with the screen', async () => {
    const { port, controls } = fakeHost()
    const { unmount } = render(screenOn(port))
    await screen.findByText(FIRST_ENTRY)

    const token = controls.standings.tokenOf(SESSION_MAIN)
    expect(token).toBeDefined()
    expect(controls.standings.opens).toEqual([
      { sessionId: SESSION_MAIN, grantId: null, opening: token }
    ])
    const asked = controls.standings.carried.filter((call) => call.sessionId === SESSION_MAIN)
    expect(asked.length).toBeGreaterThan(0)
    expect(asked.every((call) => call.opening === token)).toBe(true)

    unmount()
    expect(controls.standings.leaves).toEqual([{ sessionId: SESSION_MAIN, opening: token }])
  })

  it('leaves an opening whose open the host has not yet answered', async () => {
    const { port, controls } = fakeHost()
    const held = controls.hold('openSession')
    const { unmount } = render(screenOn(port))
    await waitFor(() => {
      expect(held.count).toBe(1)
    })
    const [opened] = controls.standings.opens
    unmount()
    expect(controls.standings.leaves).toEqual([
      { sessionId: SESSION_MAIN, opening: opened?.opening }
    ])
    held.release()
  })

  it('takes a new token for each open, and asks nothing under an opening it has replaced', async () => {
    const { port, controls } = fakeHost()
    const view = render(screenOn(port))
    await screen.findByText(FIRST_ENTRY)
    const first = controls.standings.tokenOf(SESSION_MAIN)

    controls.standings.answerOpens(SESSION_MAIN, share(['session.view', 'agent.prompt']))
    view.rerender(screenOn(port, SHARE))
    await waitFor(() => {
      expect(controls.standings.opens).toHaveLength(2)
    })
    const second = controls.standings.tokenOf(SESSION_MAIN)
    expect(second).toBeDefined()
    expect(second).not.toBe(first)
    expect(controls.standings.opens[1]).toEqual({
      sessionId: SESSION_MAIN,
      grantId: SHARE,
      opening: second
    })
    expect(controls.standings.leaves).toEqual([{ sessionId: SESSION_MAIN, opening: first }])
    // What the screen asks after the second open names the second.
    await waitFor(() => {
      const last = controls.standings.carried.at(-1)
      expect(last?.opening).toBe(second)
    })
  })

  it('reads nothing until the host says the session is open, and again when it does', async () => {
    const { port, controls } = fakeHost()
    controls.standings.answerOpens(SESSION_MAIN, {
      state: 'reconnecting',
      reason: 'Contact with the session was lost.'
    })
    render(screenOn(port))
    expect(await screen.findByText('Not in contact with this host')).toBeInTheDocument()
    expect(controls.standings.carried).toEqual([])

    act(() => {
      controls.standings.say(SESSION_MAIN, share(['session.view']))
    })
    await screen.findByText(FIRST_ENTRY)
    expect(screen.queryByText('Not in contact with this host')).toBeNull()
  })
})

describe('what a screen may do is what the host decided for its opening', () => {
  async function typed(text: string): Promise<ReturnType<typeof userEvent.setup>> {
    const person = userEvent.setup()
    await screen.findByText(FIRST_ENTRY)
    await person.type(screen.getByLabelText('Message this session'), text)
    return person
  }

  it('offers Send only where the opening holds the right to prompt', async () => {
    const { port, controls } = fakeHost()
    controls.standings.answerOpens(SESSION_MAIN, share(['session.view']))
    render(screenOn(port, SHARE))
    await typed('go on')
    expect((await screen.findAllByText('This device was not granted this.')).length).toBeGreaterThan(0)
    expect(screen.getByRole('button', { name: 'Send' })).toBeDisabled()

    act(() => {
      controls.standings.say(SESSION_MAIN, share(['session.view', 'agent.prompt']))
    })
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Send' })).toBeEnabled()
    })
  })

  it('offers what a share holds although the pairing holds less', async () => {
    const { port, controls } = fakeHost()
    controls.setRights(['session.view'])
    controls.standings.answerOpens(SESSION_MAIN, share(['session.view', 'agent.prompt']))
    render(screenOn(port, SHARE))
    await typed('go on')
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Send' })).toBeEnabled()
    })
  })

  it('follows the connection’s rights for a session opened under the pairing', async () => {
    const { port, controls } = fakeHost()
    render(screenOn(port))
    await typed('go on')
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Send' })).toBeEnabled()
    })
    act(() => {
      controls.setRights(['session.view'])
    })
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Send' })).toBeDisabled()
    })
  })

  it('replaces the terminal by one line when the share does not include the live screen', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    controls.standings.answerOpens(
      SESSION_MAIN,
      share(['session.view', 'terminal.input'], { includes_live_screen: false })
    )
    render(screenOn(port, SHARE))
    await screen.findByText(FIRST_ENTRY)
    await person.click(screen.getByRole('tab', { name: 'Terminal' }))
    expect(await screen.findByTestId('no-live-screen')).toHaveTextContent(
      'This share does not include the live screen.'
    )
    expect(screen.queryByTestId('mobile-terminal')).toBeNull()
    expect(controls.terminalViews).toHaveLength(0)
  })

  it('explains a terminal the share does not let the person type into, and takes control only with the right', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    controls.standings.answerOpens(SESSION_MAIN, share(['session.view']))
    render(screenOn(port, SHARE))
    await screen.findByText(FIRST_ENTRY)
    await person.click(screen.getByRole('tab', { name: 'Terminal' }))
    await screen.findByTestId('mobile-terminal')
    expect(await screen.findByTestId('no-terminal-input')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Take control' })).toBeDisabled()

    act(() => {
      controls.standings.say(SESSION_MAIN, share(['session.view', 'terminal.input']))
    })
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Take control' })).toBeEnabled()
    })
    expect(screen.queryByTestId('no-terminal-input')).toBeNull()
  })
})

describe('an opening that is over', () => {
  it('keeps what was read, turns off what sends, and says why with the way out', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    controls.standings.answerOpens(SESSION_MAIN, share(['session.view', 'agent.prompt']))
    let left = 0
    render(
      screenOn(port, SHARE, () => {
        left += 1
      })
    )
    await screen.findByText(FIRST_ENTRY)
    await person.type(screen.getByLabelText('Message this session'), 'one more thing')
    expect(screen.getByRole('button', { name: 'Send' })).toBeEnabled()

    act(() => {
      controls.standings.say(SESSION_MAIN, { state: 'ended', reason: 'revoked' })
    })

    const banner = await screen.findByTestId('standing-banner')
    expect(banner).toHaveTextContent('This share ended')
    expect(banner).toHaveTextContent('stopped sharing it')
    expect(banner).toHaveTextContent(/Heard at/)
    // What was read stays, the person's draft stays, and nothing more can be sent.
    expect(screen.getByText(FIRST_ENTRY)).toBeInTheDocument()
    expect(screen.getByLabelText('Message this session')).toHaveValue('one more thing')
    expect(screen.getByRole('button', { name: 'Send' })).toBeDisabled()
    expect(
      screen.getByText('Nothing more can be sent to this session from here.')
    ).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Try again' })).toBeNull()
    // It is said once, in the status region that was already there.
    expect(screen.getByTestId('standing-status')).toHaveTextContent('This share ended')

    await person.click(within(banner).getByRole('button', { name: 'Back' }))
    expect(left).toBe(1)
  })

  it('says an expired share’s scheduled end', async () => {
    const { port, controls } = fakeHost()
    const endsAt = Date.UTC(2026, 9, 12, 12, 30)
    controls.standings.answerOpens(SESSION_MAIN, share(['session.view'], { ends_at_ms: endsAt }))
    render(screenOn(port, SHARE))
    await screen.findByText(FIRST_ENTRY)
    act(() => {
      controls.standings.say(SESSION_MAIN, { state: 'ended', reason: 'expired' })
    })
    const banner = await screen.findByTestId('standing-banner')
    expect(banner).toHaveTextContent('This share ended')
    expect(banner).toHaveTextContent('It was scheduled to end on')
  })

  it('says a closed session in its own words', async () => {
    const { port, controls } = fakeHost()
    render(screenOn(port))
    await screen.findByText(FIRST_ENTRY)
    act(() => {
      controls.standings.say(SESSION_MAIN, { state: 'closed' })
    })
    expect(await screen.findByTestId('standing-banner')).toHaveTextContent(
      'This session has closed'
    )
    expect(screen.getByText(FIRST_ENTRY)).toBeInTheDocument()
  })

  it('moves the focus to the banner only when the control the focus was on is turned off', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    controls.standings.answerOpens(SESSION_MAIN, share(['session.view', 'agent.prompt']))
    render(screenOn(port, SHARE))
    await screen.findByText(FIRST_ENTRY)
    const field = screen.getByLabelText('Message this session')
    await person.type(field, 'hello')

    // The field stays usable, so the focus stays on it.
    act(() => {
      controls.standings.say(SESSION_MAIN, { state: 'closed' })
    })
    await screen.findByTestId('standing-banner')
    expect(field).toHaveFocus()
  })

  it('moves the focus to the banner when Send, which has it, is turned off', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    controls.standings.answerOpens(SESSION_MAIN, share(['session.view', 'agent.prompt']))
    render(screenOn(port, SHARE))
    await screen.findByText(FIRST_ENTRY)
    await person.type(screen.getByLabelText('Message this session'), 'hello')
    const send = screen.getByRole('button', { name: 'Send' })
    act(() => {
      send.focus()
    })
    expect(send).toHaveFocus()

    act(() => {
      controls.standings.say(SESSION_MAIN, { state: 'ended', reason: 'revoked' })
    })
    const banner = await screen.findByTestId('standing-banner')
    await waitFor(() => {
      expect(banner).toHaveFocus()
    })
  })

  it('says the host’s sentence for a refusal, and Try again opens the session as a new opening', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    controls.standings.answerOpens(SESSION_MAIN, {
      code: 'PERMISSION_DENIED',
      message: 'This device holds no share of that session.'
    })
    render(screenOn(port))

    const banner = await screen.findByTestId('standing-banner')
    expect(banner).toHaveTextContent('This device holds no share of that session.')
    expect(within(banner).getByRole('button', { name: 'Back' })).toBeInTheDocument()
    const first = controls.standings.opens[0]?.opening
    expect(screen.queryByText(FIRST_ENTRY)).toBeNull()

    controls.standings.answerOpens(SESSION_MAIN, share(['session.view']))
    await person.click(within(banner).getByRole('button', { name: 'Try again' }))
    await screen.findByText(FIRST_ENTRY)
    expect(screen.queryByTestId('standing-banner')).toBeNull()
    expect(controls.standings.opens).toHaveLength(2)
    expect(controls.standings.opens[1]?.opening).not.toBe(first)
  })

  it('says contact lost in the connection’s words, never as stuck or failed, and goes on when the host is back', async () => {
    const { port, controls } = fakeHost()
    controls.setConnected(false)
    render(screenOn(port))
    expect(await screen.findByText('Not in contact with this host')).toBeInTheDocument()
    expect(document.body.textContent).not.toMatch(/stuck|failed/i)
    expect(screen.queryByTestId('standing-banner')).toBeNull()

    act(() => {
      controls.setConnected(true)
    })
    await screen.findByText(FIRST_ENTRY, undefined, { timeout: 20_000 })
    expect(screen.queryByText('Not in contact with this host')).toBeNull()
  })

  it('drops a standing that belongs to an opening it has replaced', async () => {
    const { port, controls } = fakeHost()
    const view = render(screenOn(port))
    await screen.findByText(FIRST_ENTRY)
    const first = controls.standings.tokenOf(SESSION_MAIN) ?? ''

    controls.standings.answerOpens(SESSION_MAIN, share(['session.view', 'agent.prompt']))
    view.rerender(screenOn(port, SHARE))
    await waitFor(() => {
      expect(controls.standings.opens).toHaveLength(2)
    })
    await screen.findByText(FIRST_ENTRY)

    act(() => {
      controls.standings.sayTo(SESSION_MAIN, first, { state: 'ended', reason: 'revoked' })
    })
    expect(screen.queryByTestId('standing-banner')).toBeNull()
  })
})

describe('an answer that comes after the screen opened the session again', () => {
  /** A port whose prompts answer when the test says. */
  function holdingPrompts(port: HostPort): {
    readonly port: HostPort
    readonly answer: (how: 'applied' | 'refused') => Promise<void>
    readonly count: () => number
  } {
    const waiting: ((how: 'applied' | 'refused') => void)[] = []
    return {
      port: {
        ...port,
        composerSubmit: (params, opening) =>
          new Promise((resolve, reject) => {
            waiting.push((how) => {
              if (how === 'refused') {
                reject({ code: 'PERMISSION_DENIED', message: 'This share may not prompt.' })
              } else {
                void port.composerSubmit(params, opening).then(resolve, reject)
              }
            })
          })
      },
      answer: async (how) => {
        await act(async () => {
          waiting.shift()?.(how)
          await new Promise((resolve) => {
            setTimeout(resolve, 0)
          })
        })
      },
      count: () => waiting.length
    }
  }

  it('settles its own record and shows no message of its own, and keeps what the person has typed since', async () => {
    const person = userEvent.setup()
    const host = fakeHost()
    host.controls.standings.answerOpens(SESSION_MAIN, share(['session.view', 'agent.prompt']))
    const prompts = holdingPrompts(host.port)
    const view = render(screenOn(prompts.port, SHARE))
    await screen.findByText(FIRST_ENTRY)
    await person.type(screen.getByLabelText('Message this session'), 'first')
    await person.click(screen.getByRole('button', { name: 'Send' }))
    await waitFor(() => {
      expect(prompts.count()).toBe(1)
    })

    // The screen opens the session again, and the person writes the next thing there.
    view.rerender(screenOn(prompts.port, null))
    await waitFor(() => {
      expect(host.controls.standings.opens).toHaveLength(2)
    })
    await screen.findByText(FIRST_ENTRY)
    const field = screen.getByLabelText('Message this session')
    await person.clear(field)
    await person.type(field, 'second')

    // The first opening's send is refused, late.
    await prompts.answer('refused')

    // The draft book keeps the refused text apart, and says so itself; the screen adds no refusal.
    expect(screen.getByTestId('said')).toHaveTextContent(/kept in Kept drafts/)
    expect(screen.getByTestId('said')).not.toHaveTextContent(/refused|may not prompt/)
    expect(field).toHaveValue('second')
    // The record of the send is settled as refused, whichever opening is on screen.
    expect(await screen.findByText('Refused by the host')).toBeInTheDocument()
  })

  it('shows the refusal of the opening that is on screen', async () => {
    const person = userEvent.setup()
    const host = fakeHost()
    const prompts = holdingPrompts(host.port)
    render(screenOn(prompts.port))
    await screen.findByText(FIRST_ENTRY)
    await person.type(screen.getByLabelText('Message this session'), 'first')
    await person.click(screen.getByRole('button', { name: 'Send' }))
    await waitFor(() => {
      expect(prompts.count()).toBe(1)
    })
    await prompts.answer('refused')
    expect(screen.getByTestId('said')).toHaveTextContent('This share may not prompt.')
  })

  it('does not send a prompt prepared under an opening the host no longer holds', async () => {
    const person = userEvent.setup()
    const host = fakeHost()
    render(screenOn(host.port))
    await screen.findByText(FIRST_ENTRY)
    await person.type(screen.getByLabelText('Message this session'), 'first')
    const stale = host.controls.standings.tokenOf(SESSION_MAIN)

    // Another opening of the session takes this one's place at the host, as native code does.
    await act(async () => {
      await host.port.openSession({ sessionId: SESSION_MAIN, grantId: null, opening: 'taken-over' })
    })
    expect(host.controls.standings.tokenOf(SESSION_MAIN)).toBe('taken-over')
    await person.click(screen.getByRole('button', { name: 'Send' }))

    // Refused as stale: nothing was sent, and the text is where it was.
    await waitFor(() => {
      expect(screen.getByTestId('said')).toHaveTextContent(/replaced by another opening/)
    })
    expect(screen.getByLabelText('Message this session')).toHaveValue('first')
    expect(
      host.controls.standings.carried.filter((call) => call.command === 'composerSubmit')
    ).toEqual([{ command: 'composerSubmit', sessionId: SESSION_MAIN, opening: stale }])
  })
})

describe('what a refused read does to what was read', () => {
  it('shows the refusal above the entries it did not hide, and drops it once the opening is over', async () => {
    const { port, controls } = fakeHost()
    let refusing = false
    render(
      screenOn({
        ...port,
        agentSnapshot: (params, opening) =>
          refusing
            ? Promise.reject({ code: 'RESOURCE_UNAVAILABLE', message: 'The link failed as it closed.' })
            : port.agentSnapshot(params, opening)
      })
    )
    await screen.findByText(FIRST_ENTRY)

    refusing = true
    act(() => {
      controls.setConnected(true)
    })
    expect(await screen.findByText('This conversation could not be read')).toBeInTheDocument()
    expect(screen.getByText(FIRST_ENTRY)).toBeInTheDocument()

    // The share ends while that read is the newest: what was read stays, and nothing says it could not be.
    act(() => {
      controls.standings.say(SESSION_MAIN, { state: 'ended', reason: 'revoked' })
    })
    await screen.findByTestId('standing-banner')
    expect(screen.getByText(FIRST_ENTRY)).toBeInTheDocument()
    expect(screen.queryByText('This conversation could not be read')).toBeNull()
  })

  it('shows nothing of an earlier opening’s refusal under the opening that replaced it', async () => {
    const { port, controls } = fakeHost()
    const known: { first?: string } = {}
    let refusing = false
    const asking: HostPort = {
      ...port,
      sessionAgents: (sessionId, opening) => {
        if (opening !== undefined && opening === known.first && refusing) {
          return Promise.reject({ code: 'RESOURCE_UNAVAILABLE', message: 'The link failed as it closed.' })
        }
        // The second opening's own read does not answer, so nothing it read can replace the refusal.
        if (known.first !== undefined && opening !== known.first) return new Promise(() => undefined)
        return port.sessionAgents(sessionId, opening)
      }
    }
    const view = render(screenOn(asking))
    await screen.findByText(FIRST_ENTRY)
    known.first = controls.standings.tokenOf(SESSION_MAIN)
    refusing = true
    act(() => {
      controls.setConnected(true)
    })
    expect(await screen.findByText('This conversation could not be read')).toBeInTheDocument()

    controls.standings.answerOpens(SESSION_MAIN, share(['session.view']))
    view.rerender(screenOn(asking, SHARE))
    await waitFor(() => {
      expect(controls.standings.opens).toHaveLength(2)
    })
    await waitFor(() => {
      expect(controls.standings.tokenOf(SESSION_MAIN)).not.toBe(known.first)
    })
    expect(screen.queryByText('This conversation could not be read')).toBeNull()
  })
})

describe('contact with a session being taken up again', () => {
  it('says contact was lost, not that the connection came back, while an action is unresolved', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    render(screenOn(port))
    await screen.findByText(FIRST_ENTRY)
    controls.holdMutation()
    await person.type(screen.getByLabelText('Message this session'), 'hold')
    await person.click(screen.getByRole('button', { name: 'Send' }))
    await waitFor(() => {
      expect(controls.submissions).toBe(1)
    })

    act(() => {
      controls.standings.say(SESSION_MAIN, { state: 'reconnecting', reason: 'lost' })
    })
    expect(await screen.findByText('Not in contact with this host')).toBeInTheDocument()
    expect(screen.queryByText('Connected again')).toBeNull()
  })
})

describe('what became of a send the host could not confirm', () => {
  /** A receipt of an action, at the state the host's record holds. */
  function receiptAt(action: string, state: Receipt['state']): Receipt {
    return {
      action_id: action,
      actor_id: 'device:phone',
      error: null,
      method: 'agent.prompt.submit',
      method_version: 1,
      payload_digest: '0'.repeat(64),
      reason: null,
      revision: '1',
      state,
      updated_at_ms: '0',
      accepted_deadline_ms: null
    }
  }

  const ACTION = 'f3a6c0de-0000-4000-8000-000000000001'

  /**
   * A port whose prompts the host takes and never confirms, as the real host answers an outcome it
   * cannot establish (with the action's identifier), whose record of every action is `state`, and the
   * reads it was asked for, with their openings.
   */
  function recording(port: HostPort, state: () => Receipt['state']) {
    const reads: { readonly action: string; readonly opening: string | undefined }[] = []
    const sent: (string | undefined)[] = []
    return {
      reads,
      sent,
      port: {
        ...port,
        composerSubmit: (params: Parameters<HostPort['composerSubmit']>[0], opening?: string) => {
          sent.push(opening)
          return port
            .composerSubmit(params, opening)
            .then((answer) => ({ ...answer, receipt: null, value: null, action_id: ACTION }))
        },
        actionRead: (params: { action_id: string }, opening?: string) => {
          reads.push({ action: params.action_id, opening })
          return Promise.resolve({ receipt: receiptAt(params.action_id, state()), result: null })
        }
      } as HostPort
    }
  }

  async function sendOne(person: ReturnType<typeof userEvent.setup>) {
    await screen.findByText(FIRST_ENTRY)
    await person.type(screen.getByLabelText('Message this session'), 'go on')
    await person.click(screen.getByRole('button', { name: 'Send' }))
  }

  it('reads the host’s record of the action under the screen’s opening, and settles the send by it', async () => {
    const person = userEvent.setup()
    const host = fakeHost()
    const record = recording(host.port, () => 'applied')
    render(screenOn(record.port))
    await sendOne(person)

    await waitFor(() => {
      expect(record.reads.length).toBeGreaterThan(0)
    })
    const token = host.controls.standings.tokenOf(SESSION_MAIN)
    expect(token).toBeDefined()
    expect(record.reads.every((read) => read.opening === token)).toBe(true)
    expect(await screen.findByText('Applied')).toBeInTheDocument()
    expect(screen.queryByTestId('composer-send-anyway')).toBeNull()
  })

  it('lets a person who checked send again under the same opening, as a new action, and keeps the earlier one listed', async () => {
    const person = userEvent.setup()
    const host = fakeHost()
    const record = recording(host.port, () => 'unknown')
    render(screenOn(record.port))
    await sendOne(person)
    await waitFor(() => {
      expect(record.reads.length).toBeGreaterThan(0)
    })
    const field = screen.getByLabelText('Message this session')
    await person.clear(field)
    await person.type(field, 'the next thing')
    await person.click(await screen.findByTestId('composer-send-anyway'))

    await waitFor(() => {
      expect(record.sent).toHaveLength(2)
    })
    const token = host.controls.standings.tokenOf(SESSION_MAIN)
    expect(record.sent).toEqual([token, token])
    // The earlier action is still listed as one nobody knows the end of.
    expect(await screen.findByTestId('earlier-actions')).toHaveTextContent('Outcome unknown')
  })

  it('reads nothing while the opening is not open, and reads at once when it is open again', async () => {
    const person = userEvent.setup()
    const host = fakeHost()
    const record = recording(host.port, () => 'unknown')
    render(screenOn(record.port))
    await sendOne(person)
    await waitFor(() => {
      expect(record.reads.length).toBe(1)
    })

    // The link is lost: the host is asked nothing more under this opening until it says it is open.
    act(() => {
      host.controls.standings.say(SESSION_MAIN, {
        state: 'reconnecting',
        reason: 'Contact with the session was lost.'
      })
    })
    await screen.findByText('Not in contact with this host')
    expect(record.reads).toHaveLength(1)

    act(() => {
      host.controls.standings.say(SESSION_MAIN, share(['session.view', 'agent.prompt']))
    })
    await waitFor(() => {
      expect(record.reads).toHaveLength(2)
    })
    expect(record.reads[1]?.opening).toBe(record.reads[0]?.opening)
  })
})

describe('the terminal under an opening', () => {
  it('says no terminal is shown, and not that it is attaching, once the opening is over', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    controls.standings.answerOpens(SESSION_MAIN, share(['session.view']))
    render(screenOn(port, SHARE))
    await screen.findByText(FIRST_ENTRY)
    act(() => {
      controls.standings.say(SESSION_MAIN, { state: 'ended', reason: 'revoked' })
    })
    await screen.findByTestId('standing-banner')
    await person.click(screen.getByRole('tab', { name: 'Terminal' }))
    expect(await screen.findByTestId('terminal-unavailable')).toHaveTextContent(
      'no longer open here'
    )
    expect(screen.queryByTestId('terminal-presentation')).toBeNull()
    expect(controls.terminalViews).toHaveLength(0)
  })

  it('shows nothing of another opening’s screen under the new opening', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    controls.standings.answerOpens(SESSION_MAIN, share(['session.view', 'terminal.input']))
    const view = render(screenOn(port, SHARE))
    await screen.findByText(FIRST_ENTRY)
    await person.click(screen.getByRole('tab', { name: 'Terminal' }))
    await waitFor(() => {
      expect(screen.getAllByTestId('mobile-terminal-line').length).toBeGreaterThan(0)
    })

    // Another opening of the session, whose own view has not drawn yet.
    controls.holdTerminalViews()
    controls.standings.answerOpens(SESSION_MAIN, share(['session.view', 'terminal.input']))
    view.rerender(screenOn(port, null))
    await waitFor(() => {
      expect(controls.standings.opens).toHaveLength(2)
    })
    await waitFor(() => {
      expect(controls.terminalViews.length).toBeGreaterThan(1)
    })
    expect(screen.queryAllByTestId('mobile-terminal-line')).toHaveLength(0)
  })

  it('gives back control the opening no longer lets the person use, and stops what the keys send', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    controls.standings.answerOpens(SESSION_MAIN, share(['session.view', 'terminal.input']))
    render(screenOn(port, SHARE))
    await screen.findByText(FIRST_ENTRY)
    await person.click(screen.getByRole('tab', { name: 'Terminal' }))
    await waitFor(() => {
      expect(screen.getAllByTestId('mobile-terminal-line').length).toBeGreaterThan(0)
    })
    await person.click(screen.getByRole('button', { name: 'Take control' }))
    act(() => {
      controls.terminalViews[0]?.grantControl()
    })
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Escape' })).toBeEnabled()
    })

    // The host's decision changes under a lease the person holds.
    act(() => {
      controls.standings.say(SESSION_MAIN, share(['session.view']))
    })
    // The keys are off as soon as the standing changes.
    expect(screen.getByRole('button', { name: 'Escape' })).toBeDisabled()
    await waitFor(() => {
      expect(controls.terminalViews[0]?.inputs.at(-1)?.kind).toBe('release')
    })
  })
})

describe('the rights a pairing and a share hold', () => {
  it('gives a pairing what the connection holds and a share what the share holds', async () => {
    const { rightsOf } = await import('../../src/model/openings')
    const open = (via: 'pairing' | 'share', actions: ActionRight[]) => ({
      token: 't',
      grantId: null,
      standing: { ...share(actions), via } as SessionStanding,
      held: null,
      heardAtMs: 0,
      told: 1
    })
    const narrow: readonly ActionRight[] = ['session.view']
    const wide: readonly ActionRight[] = ['session.view', 'agent.prompt']
    // A pairing's opening is narrowed by the connection, and unknown while the connection is.
    expect(rightsOf(open('pairing', ['session.view', 'agent.prompt']), narrow)).toEqual(['session.view'])
    expect(rightsOf(open('pairing', ['session.view', 'agent.prompt']), null)).toBeNull()
    // A share's rights are its own, whatever the connection holds.
    expect(rightsOf(open('share', ['session.view', 'agent.prompt']), narrow)).toEqual(wide)
    expect(rightsOf(open('share', ['session.view', 'agent.prompt']), null)).toEqual(wide)
  })
})

describe('answers that arrive out of order', () => {
  it('takes no answer to an open of an opening it has replaced', async () => {
    const { port, controls } = fakeHost()
    controls.standings.answerOpens(SESSION_MAIN, { state: 'ended', reason: 'revoked' })
    const held = controls.hold('openSession')
    const view = render(screenOn(port, SHARE))
    await waitFor(() => {
      expect(held.count).toBe(1)
    })
    // The screen opens the session again while the first answer is on its way.
    controls.standings.answerOpens(SESSION_MAIN, share(['session.view', 'agent.prompt']))
    view.rerender(screenOn(port, null))
    await waitFor(() => {
      expect(held.count).toBe(2)
    })
    // The second answers first and the first, which says the share ended, after it.
    await act(async () => {
      held.answer(1)
      await new Promise((resolve) => {
        setTimeout(resolve, 0)
      })
    })
    await screen.findByText(FIRST_ENTRY)
    await act(async () => {
      held.answer(0)
      await new Promise((resolve) => {
        setTimeout(resolve, 0)
      })
    })
    expect(screen.queryByTestId('standing-banner')).toBeNull()
  })

  it('takes an event heard before the answer as newer than it', async () => {
    const { port, controls } = fakeHost()
    const held = controls.hold('openSession')
    render(screenOn(port))
    await waitFor(() => {
      expect(held.count).toBe(1)
    })
    act(() => {
      controls.standings.say(SESSION_MAIN, { state: 'closed' })
    })
    await screen.findByTestId('standing-banner')
    // The open's own answer, made before the event, comes after it and says the session is open.
    await act(async () => {
      held.release()
      await new Promise((resolve) => {
        setTimeout(resolve, 0)
      })
    })
    expect(screen.getByTestId('standing-banner')).toHaveTextContent('This session has closed')
  })
})

describe('a terminal that ended while its opening stayed open', () => {
  it('attaches again when the host says the session is open again', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    render(screenOn(port))
    await screen.findByText(FIRST_ENTRY)
    await person.click(screen.getByRole('tab', { name: 'Terminal' }))
    await waitFor(() => {
      expect(screen.getAllByTestId('mobile-terminal-line').length).toBeGreaterThan(0)
    })
    act(() => {
      controls.terminalViews[0]?.end('The connection to this session ended.')
    })
    await screen.findByText('This terminal has ended')
    expect(controls.terminalViews).toHaveLength(1)

    // Native code asked the host again on the screen's link, and the host says the session is open.
    act(() => {
      controls.standings.say(SESSION_MAIN, {
        state: 'open',
        via: 'owner',
        grant_id: '',
        actions: ['session.view', 'agent.prompt', 'terminal.input'],
        includes_live_screen: true,
        history_from_ms: null,
        ends_at_ms: null
      })
    })
    await waitFor(() => {
      expect(controls.terminalViews).toHaveLength(2)
    })
  })
})

describe('a result that comes after the screen opened the session again', () => {
  /** A port whose prompt answers are held by the fake host until the test releases them. */
  async function sentUnderTheFirst(): Promise<{
    readonly person: ReturnType<typeof userEvent.setup>
    readonly view: ReturnType<typeof render>
    readonly port: HostPort
    readonly held: ReturnType<ReturnType<typeof fakeHost>['controls']['holdMutation']>
  }> {
    const person = userEvent.setup()
    const host = fakeHost()
    host.controls.standings.answerOpens(SESSION_MAIN, share(['session.view', 'agent.prompt']))
    const view = render(screenOn(host.port, SHARE))
    await screen.findByText(FIRST_ENTRY)
    const held = host.controls.holdMutation()
    await person.type(screen.getByLabelText('Message this session'), 'first')
    await person.click(screen.getByRole('button', { name: 'Send' }))
    await waitFor(() => {
      expect(host.controls.submissions).toBe(1)
    })
    return { person, view, port: host.port, held }
  }

  it('clears the draft that still holds what was sent, and labels the record as sent earlier', async () => {
    const { view, port, held } = await sentUnderTheFirst()
    view.rerender(screenOn(port, null))
    await screen.findByText(FIRST_ENTRY)
    // The first opening's send is taken, late; the composer still holds exactly what was sent.
    await act(async () => {
      held.release()
      await new Promise((resolve) => {
        setTimeout(resolve, 0)
      })
    })
    await waitFor(() => {
      expect(screen.getByLabelText('Message this session')).toHaveValue('')
    })
    expect(screen.getByTestId('sent-earlier')).toBeInTheDocument()
    expect(screen.getByTestId('said')).not.toHaveTextContent(/refused/)
  })

  it('keeps what the person wrote since', async () => {
    const { person, view, port, held } = await sentUnderTheFirst()
    view.rerender(screenOn(port, null))
    await screen.findByText(FIRST_ENTRY)
    const field = screen.getByLabelText('Message this session')
    await person.clear(field)
    await person.type(field, 'second')
    await act(async () => {
      held.release()
      await new Promise((resolve) => {
        setTimeout(resolve, 0)
      })
    })
    expect(field).toHaveValue('second')
  })
})
