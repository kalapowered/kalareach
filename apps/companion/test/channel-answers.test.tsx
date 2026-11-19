/**
 * An answer a channel took ends as an outcome nobody can establish, and says so (KR-REQ-12.18).
 *
 * These render the real application against the scripted host, whose Claude Code instance answers
 * as the desktop host tells such an answer: the action and nothing else, the request held as
 * uncertain.
 */

import { describe, expect, it } from 'vitest'
import { act, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { App } from '../src/App'
import { AppProvider } from '../src/app/state'
import { fakeHost } from '../src/host/fake'
import { endsAsChannelAnswer } from '../src/model/receipts'

const SESSION_MAIN = '8a7b6c50-22bb-4c3d-8e4f-000000000101'

function start(lostAnswers: number, unrecordedAnswers = 0): ReturnType<typeof fakeHost>['controls'] {
  const { port, controls } = fakeHost()
  controls.records.useChannel(SESSION_MAIN, lostAnswers, unrecordedAnswers)
  render(
    <AppProvider port={port} initialPlace={{ view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' }}>
      <App />
    </AppProvider>
  )
  return controls
}

/** Lets everything a settled promise has queued run, the way a macrotask does, without waiting for time. */
async function settle(): Promise<void> {
  await act(async () => {
    await new Promise((resolve) => setTimeout(resolve, 0))
  })
}

async function allow(): Promise<void> {
  const approval = await screen.findByTestId('approval')
  await userEvent.click(within(approval).getByRole('button', { name: 'Allow once' }))
}

describe('an answer a channel took', () => {
  it('says the host cannot tell whether it was taken, lets go of the action, and keeps a line beside the request', async () => {
    const controls = start(0)
    await allow()
    expect(await screen.findByText(/does not confirm answers/)).toBeInTheDocument()
    expect(screen.queryByText(/could not confirm what became of that/)).toBeNull()
    await waitFor(() => {
      expect(controls.releasedActions).toHaveLength(1)
    })
    expect(controls.records.agentOf(SESSION_MAIN).resources[0]?.state).toBe('uncertain')
    // The request leaves the list of what a person can answer; the line that stays does not.
    await waitFor(() => {
      expect(screen.queryByTestId('approval')).toBeNull()
    })
    expect(await screen.findByTestId('approval-unconfirmed')).toHaveTextContent(
      /cannot tell whether Claude Code took the answer to this request/
    )
  })

  it('keeps the ordinary words, and does not let go, for an answer that was lost on the way back', async () => {
    const controls = start(1)
    await allow()
    expect(await screen.findByText(/could not confirm what became of that/)).toBeInTheDocument()
    expect(screen.queryByText(/does not confirm answers/)).toBeNull()
    await act(async () => {
      await Promise.resolve()
    })
    expect(controls.releasedActions).toHaveLength(0)
  })

  it('tries a release again with the next read when the first did not reach the session', async () => {
    const { port, controls } = fakeHost()
    controls.records.useChannel(SESSION_MAIN, 0)
    controls.failReleases(1)
    render(
      <AppProvider port={port} initialPlace={{ view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' }}>
        <App />
      </AppProvider>
    )
    await allow()
    await waitFor(() => {
      expect(controls.releasedActions).toHaveLength(1)
    })
  })
})

describe('an answer the host cannot tell was taken, on a paired route', () => {
  it('lets go of nothing when the host holds no receipt for the answer, and says the same words', async () => {
    const controls = start(0, 1)
    await allow()
    expect(await screen.findByText(/does not confirm answers/)).toBeInTheDocument()
    await waitFor(() => {
      expect(controls.readActions).toHaveLength(1)
    })
    await settle()
    // The read answered NOT_FOUND: the worker never held the answer, so there is nothing to let go of.
    expect(controls.releasedActions).toHaveLength(0)
    expect(controls.releaseAttempts).toBe(0)
  })

  it('asks for the receipt before it lets go, and lets go of an answer whose receipt reads unknown', async () => {
    const controls = start(0)
    await allow()
    await waitFor(() => {
      expect(controls.releasedActions).toHaveLength(1)
    })
    expect(controls.readActions).toEqual(controls.releasedActions)
  })
})

describe('a release that is still on its way', () => {
  it('is not asked for a second time by the read that follows the answer', async () => {
    const { port, controls } = fakeHost()
    controls.records.useChannel(SESSION_MAIN, 0)
    const finish = controls.holdNextRelease()
    render(
      <AppProvider port={port} initialPlace={{ view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' }}>
        <App />
      </AppProvider>
    )
    await allow()
    // The request now stands as a line beside the others, which the read after the answer drew.
    await screen.findByTestId('approval-unconfirmed')
    await waitFor(() => {
      expect(controls.releaseAttempts).toBe(1)
    })
    await settle()
    expect(controls.releaseAttempts).toBe(1)
    finish()
    await waitFor(() => {
      expect(controls.releasedActions).toHaveLength(1)
    })
  })
})

describe('the lines that stay beside the requests', () => {
  it('each name their request and how long ago it was asked, and the oldest are counted', async () => {
    const { port, controls } = fakeHost()
    controls.records.useChannel(SESSION_MAIN, 0)
    controls.records.holdAnswered(SESSION_MAIN, 7)
    render(
      <AppProvider port={port} initialPlace={{ view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' }}>
        <App />
      </AppProvider>
    )
    const lines = await screen.findAllByTestId('approval-unconfirmed')
    // The five asked most recently, newest first, each with its own request and its age.
    expect(lines).toHaveLength(5)
    lines.forEach((line, index) => {
      expect(line).toHaveTextContent(new RegExp(`^Request earlier-${String(7 - index)}, asked .+ ago\\.`))
      expect(line).toHaveTextContent(/cannot tell whether Claude Code took the answer to this request/)
    })
    expect(screen.getByTestId('approval-unconfirmed-more')).toHaveTextContent(
      /^2 more answers are in the same state/
    )
  })

  it('keep one line for each of up to five, and no count line', async () => {
    const { port, controls } = fakeHost()
    controls.records.useChannel(SESSION_MAIN, 0)
    controls.records.holdAnswered(SESSION_MAIN, 5)
    render(
      <AppProvider port={port} initialPlace={{ view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' }}>
        <App />
      </AppProvider>
    )
    expect(await screen.findAllByTestId('approval-unconfirmed')).toHaveLength(5)
    expect(screen.queryByTestId('approval-unconfirmed-more')).toBeNull()
  })
})

describe('an unknown outcome that is not a channel end', () => {
  const unknown = { receipt: null, value: null, action_id: 'action-1', answer_lost: false }

  it('keeps the host’s own words and is never let go, whatever the package', () => {
    // The host's own word that it cannot tell, for a package that confirms answers: not a channel end.
    expect(endsAsChannelAnswer(unknown, false)).toBe(false)
    // The same word for a channel package is one.
    expect(endsAsChannelAnswer(unknown, true)).toBe(true)
    // A lost answer is not one for any package.
    expect(endsAsChannelAnswer({ ...unknown, answer_lost: true }, true)).toBe(false)
    expect(endsAsChannelAnswer({ ...unknown, answer_lost: true }, false)).toBe(false)
  })
})
