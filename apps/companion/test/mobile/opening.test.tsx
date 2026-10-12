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
import type { ActionRight } from '@kalareach/protocol'

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

  it('offers what a share holds although the pairing holds less, and what the host removes from a pairing at once', async () => {
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
    expect(banner).toHaveTextContent('It was scheduled to end at')
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
