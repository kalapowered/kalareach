/**
 * An agent's questions, answered the way a person answers them.
 *
 * These render the real application against the scripted host. The questions are the worker's: the
 * page shows who the worker verified asked, sends an answer only on a completed press and names the
 * revision it was shown, and an answer the worker could not take is kept on this device and is not
 * sent again by anything but the person.
 */

import { describe, expect, it } from 'vitest'
import { act, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { App } from '../src/App'
import { AppProvider, type Place } from '../src/app/state'
import { fakeHost, type FakeHostControls } from '../src/host/fake'
import type { HostPort } from '../src/host/port'
import { QUESTION_CONFIRM, QUESTION_SELECT } from '../src/host/fake-questions'

const SESSION_BUILD = '8a7b6c50-22bb-4c3d-8e4f-000000000102'

function start(initialPlace: Place = { view: 'attention' }): { controls: FakeHostControls } {
  const { port, controls } = fakeHost()
  render(
    <AppProvider port={port} initialPlace={initialPlace}>
      <App />
    </AppProvider>
  )
  return { controls }
}

/** The question articles shown now, by the question each asks. */
async function questionAbout(text: string): Promise<HTMLElement> {
  const asked = await screen.findAllByTestId('question')
  const found = asked.find((each) => within(each).queryByText(text) !== null)
  if (found === undefined) throw new Error(`no question asks "${text}"`)
  return found
}

const WHICH_BRANCH = 'Which branch should the release be cut from?'
const PUSH_ANYWAY = 'Push the branch anyway?'

describe('who asked, and what', () => {
  it('names the program the worker verified, and the name it gave itself as its own', async () => {
    start()
    const question = await questionAbout(WHICH_BRANCH)
    const asker = within(question).getByTestId('question-asker')
    expect(asker.textContent).toContain('claude')
    expect(asker.textContent).toContain('process 4242')
    expect(asker.textContent).toMatch(/calls itself “Claude Code” \(not verified\)/)
    expect(within(question).getByTestId('question-context').textContent).toContain(
      'two failing tests'
    )
  })
})

describe('the inbox lists a session’s questions once', () => {
  it('shows one panel of questions for a session, however many rows the host raised for them', async () => {
    const { port } = fakeHost()
    // The host raises a row for each question, and another for the same question when it has waited
    // for a while: two rows, one session.
    const doubled: HostPort = {
      ...port,
      attentionRead: async (params) => {
        const read = await port.attentionRead(params)
        const asked = read.items.find((item) => item.rule === 'attention.pending_input')
        if (asked === undefined) return read
        return {
          ...read,
          items: [
            ...read.items,
            { ...asked, key: `${asked.key}|idle`, rule: 'attention.input_idle_reminder' as const }
          ]
        }
      }
    }
    render(
      <AppProvider port={doubled}>
        <App />
      </AppProvider>
    )
    await questionAbout(WHICH_BRANCH)
    await waitFor(() => {
      expect(screen.getAllByTestId('attention-pending_decision').length).toBeGreaterThan(1)
    })
    expect(screen.getAllByTestId('questions')).toHaveLength(1)
    expect(screen.getAllByRole('radio', { name: 'main' })).toHaveLength(1)
  })
})

describe('answering on a completed press (KR-REQ-13.07)', () => {
  it('sends nothing on pointer-down, and one answer naming the revision shown on the release', async () => {
    const { controls } = start()
    const question = await questionAbout(WHICH_BRANCH)
    const person = userEvent.setup()
    await person.click(within(question).getByRole('radio', { name: 'release/2026-09' }))
    const send = within(question).getByRole('button', { name: 'Send answer' })

    await person.pointer({ keys: '[MouseLeft>]', target: send })
    expect(controls.questions.sent).toHaveLength(0)

    await person.pointer({ keys: '[/MouseLeft]', target: send })
    expect(await screen.findByText('Your answer was recorded.')).toBeInTheDocument()
    expect(controls.questions.sent).toEqual([
      {
        session_id: SESSION_BUILD,
        question_id: QUESTION_SELECT,
        expected_revision: '2',
        answer: { kind: 'choice', choice_id: 'release' }
      }
    ])
    await waitFor(() => {
      expect(screen.queryByText(WHICH_BRANCH)).toBeNull()
    })
  })

  it('offers no Send until the form makes an answer', async () => {
    start()
    const question = await questionAbout(WHICH_BRANCH)
    const person = userEvent.setup()
    const send = within(question).getByRole('button', { name: 'Send answer' })
    expect(send).toBeDisabled()
    await person.click(within(question).getByRole('radio', { name: 'Something else' }))
    expect(send).toBeDisabled()
    await person.type(within(question).getByLabelText('What you would say instead'), 'a tag')
    expect(send).toBeEnabled()
  })

  it('sends the free-text option as its own answer, never as a listed choice', async () => {
    const { controls } = start()
    const question = await questionAbout(WHICH_BRANCH)
    const person = userEvent.setup()
    await person.click(within(question).getByRole('radio', { name: 'Something else' }))
    await person.type(
      within(question).getByLabelText('What you would say instead'),
      'cut it from the v2 tag'
    )
    await person.click(within(question).getByRole('button', { name: 'Send answer' }))
    await screen.findByText('Your answer was recorded.')
    expect(controls.questions.sent[0]?.answer).toEqual({
      kind: 'other',
      text: 'cut it from the v2 tag'
    })
  })

  it('reads a yes or a no as a decision, and Something else as text and not as a yes', async () => {
    const { controls } = start()
    const question = await questionAbout(PUSH_ANYWAY)
    const person = userEvent.setup()
    await person.click(within(question).getByRole('radio', { name: 'No' }))
    await person.click(within(question).getByRole('button', { name: 'Send answer' }))
    await screen.findByText('Your answer was recorded.')
    expect(controls.questions.sent[0]).toMatchObject({
      question_id: QUESTION_CONFIRM,
      answer: { kind: 'decision', decided: false }
    })
  })
})

describe('a question that changed or ended while a person was answering', () => {
  it('keeps what was chosen when another device answered first, without a press, and says so', async () => {
    const { controls } = start()
    const question = await questionAbout(WHICH_BRANCH)
    const person = userEvent.setup()
    await person.click(within(question).getByRole('radio', { name: 'main' }))
    act(() => {
      controls.questions.answerElsewhere(QUESTION_SELECT)
    })
    // The next read stops listing the question. Its form must not go with it: the page says how it
    // ended and what had been chosen, whether or not the person pressed Send first.
    const closed = await screen.findByTestId('question-ended', undefined, { timeout: 20_000 })
    expect(within(closed).getByTestId('question-refusal')).toHaveTextContent(
      'answered by someone else'
    )
    expect(closed).toHaveTextContent('You had chosen “main”.')
    expect(controls.questions.sent).toHaveLength(0)
    await person.click(within(closed).getByRole('button', { name: 'Dismiss' }))
    expect(screen.queryByTestId('question-ended')).toBeNull()
  })

  it('shows the worker’s own refusal when the press comes before the next read', async () => {
    const { controls } = start()
    const question = await questionAbout(WHICH_BRANCH)
    const person = userEvent.setup()
    // The next reads are held, so the question is still listed when the person presses Send.
    const held = controls.hold('questionRead')
    await person.click(within(question).getByRole('radio', { name: 'main' }))
    act(() => {
      controls.questions.answerElsewhere(QUESTION_SELECT)
    })
    await person.click(within(question).getByRole('button', { name: 'Send answer' }))
    const closed = await screen.findByTestId('question-ended')
    expect(within(closed).getByTestId('question-refusal')).toHaveTextContent(
      'already answered or withdrawn'
    )
    expect(closed).toHaveTextContent('You had chosen “main”.')
    expect(controls.questions.sent).toHaveLength(0)
    held.release()
  })

  it('does not answer a revised question until the person has seen it', async () => {
    const { controls } = start()
    const question = await questionAbout(WHICH_BRANCH)
    const person = userEvent.setup()
    await person.click(within(question).getByRole('radio', { name: 'main' }))
    act(() => {
      controls.questions.revise(QUESTION_SELECT, { question: 'Which tag should it be cut from?' })
    })
    // The next read shows the revision; the answer was begun against the one before.
    await screen.findByText('Which tag should it be cut from?', undefined, { timeout: 20_000 })
    const revised = await questionAbout('Which tag should it be cut from?')
    await person.click(within(revised).getByRole('button', { name: 'Send answer' }))
    expect(await within(revised).findByTestId('question-refusal')).toHaveTextContent(
      'changed while you were answering'
    )
    expect(controls.questions.sent).toHaveLength(0)
    await person.click(within(revised).getByRole('button', { name: 'Send answer' }))
    await screen.findByText('Your answer was recorded.')
    expect(controls.questions.sent[0]?.expected_revision).toBe('3')
  })
})

describe('a question panel that opens after contact with the host ended', () => {
  it('can be answered on the rights this device last held, and the answer goes to the worker', async () => {
    const { controls } = start({ view: 'sessions' })
    const person = userEvent.setup()
    // The rights are read while the host is in contact.
    await screen.findByTestId('session-row-2')
    act(() => {
      controls.setConnected(false)
    })
    await person.click(screen.getByTestId('session-row-2'))
    const question = await questionAbout(WHICH_BRANCH)
    await person.click(within(question).getByRole('radio', { name: 'main' }))
    expect(within(question).getByRole('button', { name: 'Send answer' })).toBeEnabled()
    await person.click(within(question).getByRole('button', { name: 'Send answer' }))
    expect(await screen.findByText('Your answer was recorded.')).toBeInTheDocument()
    expect(controls.questions.sent).toHaveLength(1)
  })
})

describe('who may answer (KR-REQ-23.32)', () => {
  it('offers no answer to a device that was not granted the right, and says why', async () => {
    const { controls } = start()
    act(() => {
      controls.setRights(['session.view'])
    })
    const question = await questionAbout(WHICH_BRANCH)
    expect(within(question).getByRole('button', { name: 'Send answer' })).toBeDisabled()
    expect(within(question).getByTestId('question-unavailable')).toHaveTextContent(
      'not given the right to answer questions'
    )
  })
})

describe('an answer given while the worker cannot be reached (KR-REQ-11.63)', () => {
  it('is kept and not sent, is sent by no reconnect, and goes only when the person sends it', async () => {
    const { controls } = start()
    const question = await questionAbout(WHICH_BRANCH)
    const person = userEvent.setup()
    await person.click(within(question).getByRole('radio', { name: 'main' }))
    // The session's worker goes while the form is open: the last rights this device was told still
    // hold, so the answer can still be given, and the host checks them again when it is sent.
    act(() => {
      controls.questions.setReachable(false)
    })
    await person.click(within(question).getByRole('button', { name: 'Send answer' }))
    expect(
      await screen.findByText(/A copy of your answer is kept on this device, and it is sent again only if you send it/)
    ).toBeInTheDocument()
    const kept = await screen.findByTestId('kept-answer')
    expect(kept).toHaveTextContent('Answers kept on this device')
    expect(controls.questions.sent).toHaveLength(0)

    // Contact is back. Nothing is sent: the answer is offered, and the person sends it.
    act(() => {
      controls.questions.setReachable(true)
    })
    await waitFor(() => {
      expect(screen.getByTestId('kept-answer')).toHaveAttribute('data-standing', 'offered')
    })
    expect(controls.questions.sent).toHaveLength(0)
    await person.click(screen.getByRole('button', { name: 'Send it now' }))
    await waitFor(() => {
      expect(controls.questions.sent).toHaveLength(1)
    })
    expect(controls.questions.sent[0]).toMatchObject({
      question_id: QUESTION_SELECT,
      expected_revision: '2',
      answer: { kind: 'choice', choice_id: 'main' }
    })
    await waitFor(() => {
      expect(screen.queryByTestId('kept-answer')).toBeNull()
    })
  })

  it('is kept when contact with the host is lost and the worker cannot be reached either, and is offered when both are back', async () => {
    const { controls } = start()
    const question = await questionAbout(WHICH_BRANCH)
    const person = userEvent.setup()
    await person.click(within(question).getByRole('radio', { name: 'main' }))
    act(() => {
      controls.setConnected(false)
      controls.questions.setReachable(false)
    })
    await person.click(within(question).getByRole('button', { name: 'Send answer' }))
    expect(await screen.findByTestId('kept-answer')).toBeInTheDocument()
    expect(controls.questions.sent).toHaveLength(0)

    act(() => {
      controls.setConnected(true)
      controls.questions.setReachable(true)
    })
    await waitFor(() => {
      expect(screen.getByTestId('kept-answer')).toHaveAttribute('data-standing', 'offered')
    })
    // Contact coming back sent nothing: the person sends it.
    expect(controls.questions.sent).toHaveLength(0)
    await person.click(screen.getByRole('button', { name: 'Send it now' }))
    await waitFor(() => {
      expect(controls.questions.sent).toHaveLength(1)
    })
  })

  it('is taken by the worker when only the connection to the daemon is lost', async () => {
    const { controls } = start()
    const question = await questionAbout(WHICH_BRANCH)
    const person = userEvent.setup()
    await person.click(within(question).getByRole('radio', { name: 'main' }))
    // The worker has a link of its own: the answer reaches it, and it is recorded.
    act(() => {
      controls.setConnected(false)
    })
    await person.click(within(question).getByRole('button', { name: 'Send answer' }))
    expect(await screen.findByText('Your answer was recorded.')).toBeInTheDocument()
    expect(controls.questions.sent).toHaveLength(1)
    expect(screen.queryByTestId('kept-answer')).toBeNull()
  })

  it('stays kept, with what became of the question, when the question ended meanwhile', async () => {
    const { controls } = start()
    const question = await questionAbout(PUSH_ANYWAY)
    const person = userEvent.setup()
    await person.click(within(question).getByRole('radio', { name: 'Yes' }))
    act(() => {
      controls.questions.setReachable(false)
    })
    await person.click(within(question).getByRole('button', { name: 'Send answer' }))
    await screen.findByTestId('kept-answer')

    act(() => {
      controls.questions.expire(QUESTION_CONFIRM)
      controls.questions.setReachable(true)
    })
    await waitFor(() => {
      expect(screen.getByTestId('kept-answer')).toHaveAttribute('data-standing', 'ended')
    })
    const row = screen.getByTestId('kept-answer')
    expect(within(row).getByTestId('kept-answer-standing')).toHaveTextContent(
      'expired while your answer was kept'
    )
    expect(within(row).queryByRole('button', { name: 'Send it now' })).toBeNull()
    expect(controls.questions.sent).toHaveLength(0)

    await person.click(within(row).getByRole('button', { name: 'Discard' }))
    await waitFor(() => {
      expect(screen.queryByTestId('kept-answer')).toBeNull()
    })
  })
})
