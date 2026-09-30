/**
 * The screens, driven the way a person drives them.
 *
 * These render the real application against the scripted host. Nothing is mocked: the components
 * under test are the ones the desktop shell loads, and the answers they get are protocol values.
 */

import { describe, expect, it, vi } from 'vitest'
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { App } from '../src/App'
import { AppProvider, type Place } from '../src/app/state'
import { fakeHost, type FakeHostControls } from '../src/host/fake'
import type { HostPort } from '../src/host/port'
import { CommitButton } from '../src/components/ui'

function start(initialPlace: Place = { view: 'attention' }): { controls: FakeHostControls } {
  const { port, controls } = fakeHost()
  render(
    <AppProvider port={port} initialPlace={initialPlace}>
      <App />
    </AppProvider>
  )
  return { controls }
}

const SESSION_MAIN = '8a7b6c50-22bb-4c3d-8e4f-000000000101'

/**
 * One event of a drag, with the moment it happened.
 *
 * The release velocity is read from the last hundred milliseconds of pointer positions, and an
 * environment that stamps three events within a microsecond of each other turns a sixty-pixel drag
 * into sixty thousand pixels a second, which dismisses the surface. Saying when each one happened
 * is what makes a gesture mean the same thing on every machine.
 */
function gesture(type: string, clientY: number, timeStamp: number): PointerEvent {
  const event = new PointerEvent(type, { bubbles: true, clientY })
  Object.defineProperty(event, 'timeStamp', { value: timeStamp })
  return event
}

describe('the attention inbox', () => {
  it('keeps its four states apart, and a notice apart from all of them', async () => {
    start()
    await waitFor(() => {
      expect(screen.getByTestId('attention-list')).toBeInTheDocument()
    })
    expect(screen.getAllByTestId('attention-pending_decision').length).toBeGreaterThan(0)
    expect(screen.getByTestId('attention-failed_action')).toBeInTheDocument()
    expect(screen.getByTestId('attention-awaiting_review')).toBeInTheDocument()
    expect(screen.getByTestId('attention-disconnected')).toBeInTheDocument()
    const notice = screen.getByTestId('attention-notice')
    expect(notice.textContent).toContain('It is not a request from the host.')
    expect(within(notice).queryByTestId('approvals')).toBeNull()
  })

  it('never calls a lost connection a failure', async () => {
    start()
    const entry = await screen.findByTestId('attention-disconnected')
    expect(within(entry).getByTestId('disconnected-note').textContent).toMatch(
      /may still be running; nothing here says they are not/
    )
    expect(entry.textContent).not.toMatch(/failed|stuck|crashed/i)
  })

  it('shows what a decision is about, and what the agent sent, before it is allowed', async () => {
    start()
    const approval = await screen.findByTestId('approval')
    expect(
      within(approval).getByRole('heading', {
        name: 'Run scripts/release.sh --publish in /Users/rs/work/kalareach'
      })
    ).toBeInTheDocument()
    expect(within(approval).getByTestId('approval-source').textContent).toContain(
      '"command":["scripts/release.sh","--publish"]'
    )
    expect(within(approval).getByText(/Read by openai\.codex from openai/)).toBeInTheDocument()
    expect(within(approval).getByTestId('approval-authority').textContent).toContain(
      'with its own permissions'
    )
  })

  // KR-REQ-13.07: an approval is decided on a completed press, never on pointer-down.
  it('answers an approval only on a completed press, and reports the host’s answer', async () => {
    const { controls } = start()
    const approval = await screen.findByTestId('approval')
    const allow = within(approval).getByRole('button', { name: 'Allow once' })
    const person = userEvent.setup()

    // Pointer-down alone is feedback, not a decision.
    await person.pointer({ keys: '[MouseLeft>]', target: allow })
    expect(controls.records.agentOf(SESSION_MAIN).resources[0]?.state).toBe('pending')

    // The release completes the press.
    await person.pointer({ keys: '[/MouseLeft]', target: allow })
    expect(await screen.findByText('You chose “Allow once”.')).toBeInTheDocument()
    expect(controls.records.agentOf(SESSION_MAIN).resources[0]?.state).toBe('resolved')
    await waitFor(() => {
      expect(screen.queryByTestId('approval')).toBeNull()
    })
  })
})

describe('the whole inbox, and who may answer (KR-REQ-13.09, 11.26)', () => {
  it('reads every page of the inbox, not only the first', async () => {
    const { controls } = start()
    controls.records.raiseNotices(SESSION_MAIN, 250)
    await userEvent.click(await screen.findByRole('button', { name: 'Notices' }))
    await waitFor(() => {
      expect(screen.getAllByTestId('attention-notice')).toHaveLength(251)
    })
  })

  it('offers no decision this device was not granted, and says why', async () => {
    const { controls } = start()
    act(() => {
      controls.setRights(['session.view', 'agent.prompt'])
    })
    const approval = await screen.findByTestId('approval')
    await waitFor(() => {
      expect(within(approval).getByTestId('approval-unavailable')).toHaveTextContent(
        'This device was not granted this.'
      )
    })
    expect(within(approval).getByRole('button', { name: 'Allow once' })).toBeDisabled()
  })
})

describe('the session list', () => {
  it('shows the number, the directory, the attachment count and the state', async () => {
    start({ view: 'sessions' })
    const row = await screen.findByTestId('session-row-1')
    expect(within(row).getByText('1')).toBeInTheDocument()
    expect(within(row).getByText('/Users/rs/work/kalareach')).toBeInTheDocument()
    expect(within(row).getByTestId('attachment-count').textContent).toBe('2')
    expect(within(row).getByText('Waiting for you')).toBeInTheDocument()
  })

  it('says a state was not reported rather than guessing one', async () => {
    start({ view: 'sessions' })
    const row = await screen.findByTestId('session-row-3')
    expect(within(row).getByText('Not reported')).toBeInTheDocument()
  })
})

describe('the semantic view', () => {
  it('renders the document union and shows an unknown node as unsupported', async () => {
    const { controls } = start({ view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' })
    await screen.findByTestId('conversation')
    expect(await screen.findByText('Find why the reconnect test is flaky.')).toBeInTheDocument()

    controls.appendNode({
      id: 'n-strange',
      revision: '1',
      body: { kind: 'holographic_widget', payload: 'anything' }
    } as never)

    const unsupported = await screen.findByTestId('unsupported-node')
    expect(unsupported.textContent).toMatch(/carries no\s+action/)
    expect(within(unsupported).queryByRole('button')).toBeNull()
  })

  it('shows queued, then applied, for one submission', async () => {
    start({ view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' })
    const input = await screen.findByTestId('composer-input')
    await userEvent.type(input, 'run the tests')
    await userEvent.click(screen.getByTestId('composer-send'))

    const pending = await screen.findByTestId('pending-actions')
    await waitFor(() => {
      expect(within(pending).getByText('Applied')).toBeInTheDocument()
    })
  })

  // KR-REQ-13.12: the composer's slash commands are the ones the agent advertises.
  it('offers the commands the agent advertises when the draft starts with a slash', async () => {
    start({ view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' })
    const input = await screen.findByTestId('composer-input')
    await waitFor(() => {
      expect(input).toHaveAttribute('placeholder', 'Ask for something, or press / for a command')
    })
    await userEvent.type(input, '/com')
    const commands = await screen.findByTestId('slash-commands')
    expect(commands.textContent).toContain('/compact')
    expect(commands.textContent).toContain('Shorten the conversation so far')
    expect(commands.textContent).not.toContain('/model')

    await userEvent.click(within(commands).getByRole('button', { name: /compact/ }))
    expect(screen.getByTestId('composer-input')).toHaveValue('/compact ')
  })

  // KR-REQ-13.12: queue, steer and interrupt appear only where the binding's capabilities allow.
  it('offers queueing, steering and interrupting only where the agent can do them now', async () => {
    const { controls } = start({ view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' })
    // The main session's agent is running a turn and its upstream offers all three.
    expect(await screen.findByTestId('composer-queue')).toBeInTheDocument()
    expect(screen.getByTestId('composer-steer')).toBeInTheDocument()
    expect(screen.getByTestId('composer-interrupt')).toBeInTheDocument()

    // The turn ends: there is nothing to steer or interrupt.
    act(() => {
      controls.records.endTurn(SESSION_MAIN)
    })
    await act(async () => {
      document.dispatchEvent(new Event('visibilitychange'))
      await Promise.resolve()
    })
    await waitFor(() => {
      expect(screen.queryByTestId('composer-steer')).toBeNull()
    })
    expect(screen.queryByTestId('composer-interrupt')).toBeNull()
    expect(screen.getByTestId('composer-queue')).toBeInTheDocument()
  })

  it('offers neither a queue nor steering where the upstream offers neither', async () => {
    start({ view: 'session', sessionId: '8a7b6c50-22bb-4c3d-8e4f-000000000102', pane: 'semantic' })
    const send = await screen.findByTestId('composer-send')
    await waitFor(() => {
      expect(screen.getByTestId('composer-input')).toHaveAttribute(
        'placeholder',
        'Ask for something, or press / for a command'
      )
    })
    expect(send).toBeInTheDocument()
    expect(screen.queryByTestId('composer-queue')).toBeNull()
    expect(screen.queryByTestId('composer-steer')).toBeNull()
  })

  it('sends nothing while the binding is unverified, and says why in the host’s words', async () => {
    const { controls } = start({ view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' })
    await screen.findByTestId('composer-queue')
    act(() => {
      controls.records.suspend(SESSION_MAIN, 'The conversation changed outside this host.')
    })
    await act(async () => {
      document.dispatchEvent(new Event('visibilitychange'))
      await Promise.resolve()
    })
    await waitFor(() => {
      expect(screen.queryByTestId('composer-queue')).toBeNull()
    })
    await userEvent.type(screen.getByTestId('composer-input'), 'go on')
    expect(screen.getByTestId('composer-reason')).toHaveTextContent(
      'The conversation changed outside this host.'
    )
    expect(screen.getByTestId('composer-send')).toBeDisabled()
  })

  it('keeps the draft when the host goes out of contact, and says the draft is kept', async () => {
    const { controls } = start({ view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' })
    const input = await screen.findByTestId('composer-input')
    await userEvent.type(input, 'half a thought')

    controls.setConnected(false)

    await waitFor(() => {
      expect(screen.getByTestId('composer')).toHaveAttribute('data-draft-state', 'detached')
    })
    expect(screen.getByTestId('composer-input')).toHaveValue('half a thought')
    expect(screen.getByText(/The draft is kept here/)).toBeInTheDocument()
  })

  // KR-REQ-07.51: whether the host can be reached is a field of its own. Losing contact puts up a
  // notice of its own and leaves the session's lifecycle and application state as the host last
  // reported them, rather than turning them into a closure or a failure.
  it('keeps what the session is doing apart from whether its host can be reached', async () => {
    const { controls } = start({ view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' })
    const heading = await screen.findByText('Session 1 · Waiting for you')
    expect(screen.queryAllByText('Not in contact with this host')).toHaveLength(0)

    controls.setConnected(false)

    expect((await screen.findAllByText('Not in contact with this host')).length).toBeGreaterThan(0)
    expect(heading).toHaveTextContent('Session 1 · Waiting for you')
    expect(heading).not.toHaveTextContent(/Closed|Closing|Failed/)
  })

  it('shows a reconnect banner that never implies an action succeeded', async () => {
    const { port, controls } = fakeHost()
    // The host has not answered the queued prompt when contact is lost.
    render(
      <AppProvider
        port={{ ...port, composerQueue: () => new Promise(() => undefined) }}
        initialPlace={{ view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' }}
      >
        <App />
      </AppProvider>
    )
    const conversation = await screen.findByTestId('conversation')
    const input = screen.getByTestId('composer-input')
    await userEvent.type(input, 'run the tests')
    await userEvent.click(screen.getByTestId('composer-queue'))

    controls.setConnected(false)

    const banner = await within(conversation).findByText(
      'Not in contact with this host',
      { selector: 'strong' }
    )
    const text = banner.parentElement?.textContent ?? ''
    expect(text).toMatch(/no confirmed outcome/)
    expect(text).toMatch(/may still be running/)
    expect(text).not.toMatch(/succeeded|delivered|done/i)
  })

  it('draws the six installed profiles plus a named command at a verified empty prompt', async () => {
    start({ view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' })
    const surface = await screen.findByTestId('launch-surface')
    for (const label of ['Codex', 'Claude Code', 'OpenCode', 'Gemini', 'Kimi', 'Qoder']) {
      expect(within(surface).getByRole('button', { name: new RegExp(label) })).toBeInTheDocument()
    }
    expect(within(surface).getByRole('button', { name: /Run the test suite/ })).toBeInTheDocument()
  })

  it('disables a profile the environment does not have', async () => {
    start({ view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' })
    const surface = await screen.findByTestId('launch-surface')
    expect(within(surface).getByRole('button', { name: /Kimi/ })).toBeDisabled()
    expect(within(surface).getByRole('button', { name: /Codex/ })).toBeEnabled()
  })

  it('disables every launch button once the prompt generation moves', async () => {
    const { controls } = start({ view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' })
    const surface = await screen.findByTestId('launch-surface')
    expect(within(surface).getByRole('button', { name: /Codex/ })).toBeEnabled()

    controls.changePromptGeneration()

    await waitFor(() => {
      expect(screen.getByTestId('launch-stale')).toBeInTheDocument()
    })
    expect(within(screen.getByTestId('launch-surface')).getByRole('button', { name: /Codex/ })).toBeDisabled()
  })

  it('sends a dropped file through the transfer service and keeps it with the draft', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    render(
      <AppProvider
        port={port}
        initialPlace={{ view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' }}
      >
        <App />
      </AppProvider>
    )
    await screen.findByTestId('composer-queue')

    controls.dropFiles([
      { name: 'diagram.png', media_type: 'image/png', byte_len: 10, path: '/tmp/diagram.png' }
    ])

    await waitFor(() => {
      expect(controls.uploaded).toEqual(['/tmp/diagram.png'])
    })
    expect(await screen.findByTestId('insertion-refusal')).toHaveTextContent(
      'diagram.png is uploaded and kept with this draft.'
    )
    const files = screen.getByTestId('draft-attachments')
    expect(within(files).getByText('Uploaded')).toBeInTheDocument()
    expect(screen.queryByText(/attached\./)).toBeNull()

    // A prompt from here cannot carry it, so none is sent that would leave it behind.
    await person.type(screen.getByTestId('composer-input'), 'Look at this')
    expect(screen.getByTestId('composer-send')).toBeDisabled()
    expect(screen.getByTestId('composer-reason')).toHaveTextContent(
      'Remove them to send the text on its own.'
    )

    // Only the person takes it off, and then the text goes on its own.
    await person.click(screen.getByRole('button', { name: 'Remove diagram.png from this draft' }))
    expect(screen.queryByTestId('draft-attachments')).toBeNull()
    expect(screen.getByTestId('composer-send')).toBeEnabled()
  })

  it('sends no prompt while a dropped file uploads, or after its upload failed, until it is removed', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    let fail: (reason: unknown) => void = () => undefined
    render(
      <AppProvider
        port={{
          ...port,
          attachmentUpload: () =>
            new Promise((_, reject) => {
              fail = reject
            })
        }}
        initialPlace={{ view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' }}
      >
        <App />
      </AppProvider>
    )
    await screen.findByTestId('composer-queue')
    await person.type(screen.getByTestId('composer-input'), 'Look at this')

    controls.dropFiles([
      { name: 'diagram.png', media_type: 'image/png', byte_len: 10, path: '/tmp/diagram.png' }
    ])
    const files = await screen.findByTestId('draft-attachments')
    expect(within(files).getByText('Uploading…')).toBeInTheDocument()
    expect(screen.getByTestId('composer-send')).toBeDisabled()
    expect(screen.getByTestId('composer-queue')).toBeDisabled()

    await act(async () => {
      fail({ code: 'STORAGE_UNAVAILABLE', message: 'The staging area is full.', user_action: 'retry' })
      await Promise.resolve()
    })
    expect(await within(files).findByText('Not uploaded')).toBeInTheDocument()
    expect(screen.getByTestId('insertion-refusal')).toHaveTextContent(
      'diagram.png was not uploaded: The staging area is full.'
    )
    expect(screen.getByTestId('composer-send')).toBeDisabled()

    await person.click(screen.getByRole('button', { name: 'Remove diagram.png from this draft' }))
    expect(screen.getByTestId('composer-send')).toBeEnabled()
  })

  it('says what to do about a file that was not uploaded, in words and never the code (KR-REQ-23.57)', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    let fail: (failure: unknown) => void = () => undefined
    render(
      <AppProvider
        port={{
          ...port,
          attachmentUpload: () =>
            new Promise((_, reject) => {
              fail = reject
            })
        }}
        initialPlace={{ view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' }}
      >
        <App />
      </AppProvider>
    )
    await screen.findByTestId('composer-queue')
    await person.type(screen.getByTestId('composer-input'), 'Look at this')
    controls.dropFiles([
      { name: 'diagram.png', media_type: 'image/png', byte_len: 10, path: '/tmp/diagram.png' }
    ])
    await screen.findByTestId('draft-attachments')
    // A failure as native code sends it: the code and a colon in front of the host's words, and the
    // key of the action the code maps to.
    await act(async () => {
      fail({
        code: 'STORAGE_UNAVAILABLE',
        message: 'STORAGE_UNAVAILABLE: the staging area is full',
        user_action: 'wait'
      })
      await Promise.resolve()
    })
    expect(await screen.findByTestId('insertion-refusal')).toHaveTextContent(
      'diagram.png was not uploaded: the staging area is full. Wait a moment and try again.'
    )
    expect(screen.getByTestId('insertion-refusal')).not.toHaveTextContent('STORAGE_UNAVAILABLE')
  })

  it.each([
    ['succeeds', true],
    ['fails', false]
  ])('says nothing about a file the person removed before its upload %s', async (_, succeeds) => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    let finish: () => void = () => undefined
    render(
      <AppProvider
        port={{
          ...port,
          attachmentUpload: (path, subject) =>
            new Promise((resolve, reject) => {
              finish = () => {
                if (succeeds) resolve(port.attachmentUpload(path, subject))
                else reject({ code: 'STORAGE_UNAVAILABLE', message: 'Full.', user_action: 'retry' })
              }
            })
        }}
        initialPlace={{ view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' }}
      >
        <App />
      </AppProvider>
    )
    await screen.findByTestId('composer-queue')
    controls.dropFiles([
      { name: 'diagram.png', media_type: 'image/png', byte_len: 10, path: '/tmp/diagram.png' }
    ])
    await screen.findByTestId('draft-attachments')
    await person.click(screen.getByRole('button', { name: 'Remove diagram.png from this draft' }))
    await act(async () => {
      finish()
      await new Promise((resolve) => {
        setTimeout(resolve, 0)
      })
    })
    expect(screen.queryByTestId('draft-attachments')).toBeNull()
    expect(screen.queryByTestId('insertion-refusal')).toBeNull()
  })

  // KR-REQ-13.12: a pasted file is an attachment, and goes as a dropped one does.
  it('sends a pasted file through the transfer service as a dropped one goes', async () => {
    const { port, controls } = fakeHost()
    render(
      <AppProvider
        port={port}
        initialPlace={{ view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' }}
      >
        <App />
      </AppProvider>
    )
    await screen.findByTestId('composer-queue')
    const input = screen.getByTestId('composer-input')

    // Pasted text is text: the field takes it and nothing is uploaded.
    fireEvent.paste(input, { clipboardData: { files: [] } })
    expect(controls.uploaded).toEqual([])

    const pasted = new File([new Uint8Array([137, 80, 78, 71])], 'Screenshot.png', { type: 'image/png' })
    fireEvent.paste(input, { clipboardData: { files: [pasted] } })
    await waitFor(() => {
      expect(controls.uploaded).toEqual(['Screenshot.png'])
    })
    expect(await screen.findByTestId('insertion-refusal')).toHaveTextContent(
      'Screenshot.png is uploaded and kept with this draft.'
    )
    expect(within(screen.getByTestId('draft-attachments')).getByText('Uploaded')).toBeInTheDocument()
  })

  it('does not send a file this window was never given', async () => {
    const { port, controls } = fakeHost()
    render(
      <AppProvider
        port={port}
        initialPlace={{ view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' }}
      >
        <App />
      </AppProvider>
    )
    await screen.findByTestId('composer')

    controls.dropFiles([
      { name: 'id_ed25519', media_type: 'application/octet-stream', byte_len: 400 }
    ])

    expect(await screen.findByTestId('insertion-refusal')).toHaveTextContent(
      'was not given to this window'
    )
    expect(controls.uploaded).toEqual([])
  })
})

describe('the session view reads once it is listening (KR-REQ-13.02, KR-REQ-13.11)', () => {
  /** The application on the main session, against a host the test has prepared. */
  function openSession(port: HostPort): void {
    render(
      <AppProvider
        port={port}
        initialPlace={{ view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' }}
      >
        <App />
      </AppProvider>
    )
  }

  const LOST = 'Not in contact with this host'

  it('shows a host lost while its listeners register', async () => {
    const { port, controls } = fakeHost()
    const complete = controls.holdRegistrations()
    openSession(port)

    act(() => {
      controls.setConnected(false)
    })
    await act(async () => {
      complete()
      await Promise.resolve()
    })

    expect((await screen.findAllByText(LOST)).length).toBeGreaterThan(0)
  })

  // KR-REQ-13.11: a generation that moved while the view registered is the one its surface is
  // read at, so no button is ever drawn at the old one and a launch names the prompt that is there.
  it('names the prompt generation that moved while its listeners registered', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    const complete = controls.holdRegistrations()
    openSession(port)

    act(() => {
      controls.changePromptGeneration()
    })
    await act(async () => {
      complete()
      await Promise.resolve()
    })

    const codex = within(await screen.findByTestId('launch-surface')).getByRole('button', {
      name: /Codex/
    })
    expect(codex).toBeEnabled()
    await person.click(codex)
    expect(await screen.findByText('Codex started.')).toBeInTheDocument()
  })

  it('keeps a lost connection it heard over a session read that answers after it', async () => {
    const { port, controls } = fakeHost()
    const held = controls.hold('sessionRead')
    openSession(port)
    await waitFor(() => {
      expect(held.count).toBe(1)
    })

    act(() => {
      controls.setConnected(false)
    })
    expect((await screen.findAllByText(LOST)).length).toBeGreaterThan(0)
    // The read was made while the host was reached, and its answer arrives only now: the session
    // it describes is shown, and the connection stays as it was heard.
    await act(async () => {
      held.release()
      await Promise.resolve()
    })
    await screen.findByText('Session 1 · Waiting for you')
    expect(screen.queryAllByText(LOST).length).toBeGreaterThan(0)
  })

  // KR-REQ-13.11: the surface was read at the old generation and answers after the new one was
  // heard, so its buttons are drawn disabled.
  it('disables the launch buttons when the generation moves before the surface read answers', async () => {
    const { port, controls } = fakeHost()
    const held = controls.hold('launchSurface')
    openSession(port)
    await waitFor(() => {
      expect(held.count).toBe(1)
    })

    act(() => {
      controls.changePromptGeneration()
    })
    await act(async () => {
      held.release()
      await Promise.resolve()
    })

    const surface = await screen.findByTestId('launch-surface')
    expect(within(surface).getByRole('button', { name: /Codex/ })).toBeDisabled()
    expect(screen.getByTestId('launch-stale')).toBeInTheDocument()
  })

  // A launch answers after the person has moved to another session in the same view: the read it
  // asks for belongs to the session on screen, and nothing read for the first one is shown.
  it('shows nothing of a session it has moved away from', async () => {
    const person = userEvent.setup()
    const { port } = fakeHost()
    let finishLaunch = () => {}
    const launching: HostPort = {
      ...port,
      shellLaunch: (params, subject) =>
        new Promise((resolve, reject) => {
          finishLaunch = () => {
            port.shellLaunch(params, subject).then(resolve, reject)
          }
        })
    }
    render(
      <AppProvider port={launching} initialPlace={{ view: 'sessions' }}>
        <App />
      </AppProvider>
    )
    await person.click(await screen.findByTestId('session-row-1'))
    await screen.findByText('Session 1 · Waiting for you')
    await person.click(screen.getByRole('button', { name: 'Sessions' }))
    await person.click(await screen.findByTestId('session-row-2'))
    await screen.findByText('Session 2 · Working')
    await person.click(screen.getByRole('tab', { name: 'Session 01' }))
    await screen.findByText('Session 1 · Waiting for you')

    const codex = within(await screen.findByTestId('launch-surface')).getByRole('button', {
      name: /Codex/
    })
    await person.click(codex)
    await person.click(screen.getByRole('tab', { name: 'Session 02' }))
    await screen.findByText('Session 2 · Working')

    await act(async () => {
      finishLaunch()
      await Promise.resolve()
    })
    expect(await screen.findByText('Codex started.')).toBeInTheDocument()
    await act(async () => {
      await Promise.resolve()
    })
    expect(screen.getByText('Session 2 · Working')).toBeInTheDocument()
    expect(screen.queryByText('Session 1 · Waiting for you')).toBeNull()
  })

  // A view whose listeners could not be registered offers no launch, and trying again registers
  // them again before it reads, so a later change of prompt is heard.
  it('registers its listeners again before it reads again', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    let refusing = true
    openSession({
      ...port,
      subscribe: (listener) =>
        refusing
          ? Promise.reject({
              code: 'INTERNAL',
              message: 'The shell did not register the listener.',
              user_action: 'retry'
            })
          : port.subscribe(listener)
    })
    expect((await screen.findAllByText(LOST)).length).toBeGreaterThan(0)
    expect(screen.queryByTestId('launch-surface')).toBeNull()

    refusing = false
    await person.click(screen.getByRole('button', { name: 'Try again' }))
    const codex = () =>
      within(screen.getByTestId('launch-surface')).getByRole('button', { name: /Codex/ })
    await waitFor(() => {
      expect(codex()).toBeEnabled()
    })

    act(() => {
      controls.changePromptGeneration()
    })
    await waitFor(() => {
      expect(codex()).toBeDisabled()
    })
    expect(screen.getByTestId('launch-stale')).toBeInTheDocument()
  })

  // A surface belongs to the listeners that covered its read. Back on a session whose new
  // listeners are still registering, the surface read before is not offered again.
  it('offers no launch on a return to a session until its listeners are registered again', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    render(
      <AppProvider port={port} initialPlace={{ view: 'sessions' }}>
        <App />
      </AppProvider>
    )
    await person.click(await screen.findByTestId('session-row-1'))
    await screen.findByText('Session 1 · Waiting for you')
    await person.click(screen.getByRole('button', { name: 'Sessions' }))
    await person.click(await screen.findByTestId('session-row-2'))
    await screen.findByText('Session 2 · Working')
    await person.click(screen.getByRole('tab', { name: 'Session 01' }))
    await screen.findByTestId('launch-surface')

    const complete = controls.holdRegistrations()
    await person.click(screen.getByRole('tab', { name: 'Session 02' }))
    await person.click(screen.getByRole('tab', { name: 'Session 01' }))
    act(() => {
      controls.changePromptGeneration()
    })
    expect(screen.queryByTestId('launch-surface')).toBeNull()

    await act(async () => {
      complete()
      await Promise.resolve()
    })
    const codex = within(await screen.findByTestId('launch-surface')).getByRole('button', {
      name: /Codex/
    })
    expect(codex).toBeEnabled()
    await person.click(codex)
    expect(await screen.findByText('Codex started.')).toBeInTheDocument()
  })

  // Trying again starts new listeners, and the surface read under the old ones is not offered
  // while the new read is on its way, even once the session read has answered.
  it('offers no surface from before a retry', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    openSession(port)
    await screen.findByTestId('launch-surface')

    act(() => {
      controls.setConnected(false)
    })
    const complete = controls.holdRegistrations()
    const surface = controls.hold('launchSurface')
    await person.click(await screen.findByRole('button', { name: 'Try again' }))
    act(() => {
      controls.setConnected(true)
      controls.changePromptGeneration()
    })
    await act(async () => {
      complete()
      await Promise.resolve()
    })
    await waitFor(() => {
      expect(screen.queryAllByText(LOST)).toHaveLength(0)
    })
    expect(screen.queryByTestId('launch-surface')).toBeNull()

    await act(async () => {
      surface.release()
      await Promise.resolve()
    })
    const codex = within(await screen.findByTestId('launch-surface')).getByRole('button', {
      name: /Codex/
    })
    expect(codex).toBeEnabled()
    await person.click(codex)
    expect(await screen.findByText('Codex started.')).toBeInTheDocument()
  })

  it('shows what it read when nothing changed in between', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    const session = controls.hold('sessionRead')
    const surface = controls.hold('launchSurface')
    openSession(port)
    await waitFor(() => {
      expect([session.count, surface.count]).toEqual([1, 1])
    })

    await act(async () => {
      session.release()
      surface.release()
      await Promise.resolve()
    })

    await screen.findByText('Session 1 · Waiting for you')
    expect(screen.queryAllByText(LOST)).toHaveLength(0)
    const codex = within(screen.getByTestId('launch-surface')).getByRole('button', {
      name: /Codex/
    })
    expect(codex).toBeEnabled()
    await person.click(codex)
    expect(await screen.findByText('Codex started.')).toBeInTheDocument()
  })
})

describe('closing a session', () => {
  // KR-REQ-06.11: closing ends the terminal's processes while the conversation stays, and the
  // consequence says so as two separate facts.
  // KR-REQ-07.54: the consequence of closing is shown when close is chosen, before it is committed.
  it('says what closing does before it is committed, and that history is kept', async () => {
    start({ view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' })
    await userEvent.click(await screen.findByTestId('close-session'))
    const consequence = await screen.findByTestId('close-consequence')
    expect(consequence.textContent).toMatch(/Approvals that are waiting are invalidated/)
    expect(consequence.textContent).toMatch(/Retained history is kept/)
    expect(consequence.textContent).toMatch(/every process it owns/)
    expect(consequence.textContent).toMatch(/the conversation and\s+the recording stay/)
  })

  // KR-REQ-06.11: the session's settings present conversation persistence and process persistence
  // as two different things: the conversation outlives its agent, the terminal outlives its views.
  it('keeps what outlives the agent apart from what outlives the views', async () => {
    start({ view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' })
    await userEvent.click(await screen.findByTestId('open-settings'))
    await userEvent.click(await screen.findByRole('button', { name: 'This session' }))
    const text = (await screen.findByText(/The conversation outlives the agent that wrote it/))
      .textContent
    expect(text).toMatch(/The terminal process keeps\s+running when every view disconnects/)
    expect(text).toMatch(/These are different things/)
  })

  // KR-REQ-13.07: a control that commits does so on a completed action, not on the press.
  // KR-REQ-07.54: with the consequence shown, nothing is closed until the person commits.
  it('commits only on a completed action', async () => {
    start({ view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' })
    await userEvent.click(await screen.findByTestId('close-session'))
    const confirm = await screen.findByTestId('confirm-close')
    const person = userEvent.setup()

    await person.pointer({ keys: '[MouseLeft>]', target: confirm })
    expect(screen.queryByText(/The session is closed/)).toBeNull()

    await person.pointer({ keys: '[/MouseLeft]', target: confirm })
    expect(await screen.findByText(/The session is closed/)).toBeInTheDocument()
  })
})

describe('the sheet', () => {
  it('opens over the session rather than replacing it', async () => {
    start({ view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' })
    await userEvent.click(await screen.findByTestId('open-settings'))
    expect(await screen.findByTestId('sheet')).toBeInTheDocument()
    // The session is still there behind it.
    expect(screen.getByTestId('composer')).toBeInTheDocument()
  })

  it('closes on Escape', async () => {
    start({ view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' })
    await userEvent.click(await screen.findByTestId('open-settings'))
    const sheet = await screen.findByTestId('sheet')
    // Dismissed from where it sits, not from halfway in. A surface still on its way has almost no
    // distance left to travel, so a run that pressed Escape straight after the element appeared
    // would be watching a journey the person never makes.
    await waitFor(() => {
      expect(sheet).toHaveAttribute('data-presentation', 'here')
    })
    await userEvent.keyboard('{Escape}')
    await waitFor(() => {
      expect(screen.queryByTestId('sheet')).toBeNull()
    })
  })

  it('says it is off its rest while a finger is on it, and here again once it settles back', async () => {
    start({ view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' })
    await userEvent.click(await screen.findByTestId('open-settings'))
    const sheet = await screen.findByTestId('sheet')
    await waitFor(() => {
      expect(sheet).toHaveAttribute('data-presentation', 'here')
    })

    // Taking hold of it stops the surface wherever it is, so it is not at rest any more; letting
    // go short of a dismissal springs it back, and it says so again when it gets there. Without
    // that last part the surface would sit there claiming to be arriving for good.
    const grip = screen.getByTestId('sheet-grip')
    grip.dispatchEvent(gesture('pointerdown', 200, 1_000))
    await waitFor(() => {
      expect(sheet).toHaveAttribute('data-presentation', 'arriving')
    })
    grip.dispatchEvent(gesture('pointermove', 260, 1_016))
    grip.dispatchEvent(gesture('pointerup', 260, 1_200))

    await waitFor(() => {
      expect(sheet).toHaveAttribute('data-presentation', 'here')
    })
    // A gesture that neither travelled far enough nor carried any speed, so it stayed.
    expect(screen.getByTestId('sheet')).toBeInTheDocument()
  })

  it('says so too when the hold interrupted its arrival', async () => {
    // The frames are handed out one at a time here, so the surface is taken hold of at a place
    // this test chose rather than wherever the machine's own frames had carried it. This is the
    // case that used to leave it saying it was arriving for ever: the grab stops the spring whose
    // end would otherwise have said it had arrived.
    const frames: FrameRequestCallback[] = []
    vi.stubGlobal('requestAnimationFrame', (callback: FrameRequestCallback) => frames.push(callback))
    vi.stubGlobal('cancelAnimationFrame', () => undefined)
    try {
      start({ view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' })
      await userEvent.click(await screen.findByTestId('open-settings'))
      const sheet = await screen.findByTestId('sheet')
      // The first frame of a spring carries no time; the second advances it by one step, which
      // leaves the surface part way in and stops there because nothing else is handed out.
      await act(async () => {
        frames.shift()?.(0)
      })
      await act(async () => {
        frames.shift()?.(64)
      })
      expect(sheet).toHaveAttribute('data-presentation', 'arriving')

      const grip = screen.getByTestId('sheet-grip')
      grip.dispatchEvent(gesture('pointerdown', 300, 1_000))
      // Two hundred pixels upward and released still, which from part way in is neither far
      // enough nor fast enough to dismiss, so the surface springs back to where it sits.
      grip.dispatchEvent(gesture('pointermove', 100, 1_016))
      grip.dispatchEvent(gesture('pointerup', 100, 1_200))

      for (let step = 0; step < 200 && sheet.getAttribute('data-presentation') !== 'here'; step += 1) {
        const next = frames.shift()
        if (!next) break
        await act(async () => {
          next(16 * (step + 2))
        })
      }
      expect(sheet).toHaveAttribute('data-presentation', 'here')
      expect(screen.getByTestId('sheet')).toBeInTheDocument()
    } finally {
      vi.unstubAllGlobals()
    }
  })

  it('comes back to rest after a hold the closing outlived, without travelling', async () => {
    // Reduced motion, where the surface does not travel and a timer is what says it has arrived.
    vi.stubGlobal('matchMedia', (query: string) => ({
      matches: query.includes('prefers-reduced-motion'),
      media: query,
      onchange: null,
      addEventListener: () => undefined,
      removeEventListener: () => undefined,
      addListener: () => undefined,
      removeListener: () => undefined,
      dispatchEvent: () => false
    }))
    try {
      start({ view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' })
      await userEvent.click(await screen.findByTestId('open-settings'))
      const sheet = await screen.findByTestId('sheet')
      await waitFor(() => {
        expect(sheet).toHaveAttribute('data-presentation', 'here')
      })

      // Held when the surface was closed, so the release lands on nothing at all. The surface that
      // opens next must still come to rest rather than inheriting a finger that is long gone.
      screen.getByTestId('sheet-grip').dispatchEvent(gesture('pointerdown', 200, 1_000))
      await userEvent.keyboard('{Escape}')
      await waitFor(() => {
        expect(screen.queryByTestId('sheet')).toBeNull()
      })

      await userEvent.click(screen.getByTestId('open-settings'))
      const again = await screen.findByTestId('sheet')
      await waitFor(() => {
        expect(again).toHaveAttribute('data-presentation', 'here')
      })
    } finally {
      vi.unstubAllGlobals()
    }
  })

  // KR-REQ-13.06: with reduced motion nothing moves by itself, and a drag is still the person's
  // own motion: the surface follows the finger and back, stops dead at its edge rather than
  // stretching past it, goes back at once when let go short of a dismissal, and fades where a
  // dismissal leaves it.
  it('follows the finger with reduced motion, with nothing springing and nothing past its edge', async () => {
    vi.stubGlobal('matchMedia', (query: string) => ({
      matches: query.includes('prefers-reduced-motion'),
      media: query,
      onchange: null,
      addEventListener: () => undefined,
      removeEventListener: () => undefined,
      addListener: () => undefined,
      removeListener: () => undefined,
      dispatchEvent: () => false
    }))
    try {
      start({ view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' })
      await userEvent.click(await screen.findByTestId('open-settings'))
      const sheet = await screen.findByTestId('sheet')
      await waitFor(() => {
        expect(sheet).toHaveAttribute('data-presentation', 'here')
      })
      const grip = screen.getByTestId('sheet-grip')

      grip.dispatchEvent(gesture('pointerdown', 200, 1_000))
      grip.dispatchEvent(gesture('pointermove', 290, 1_016))
      expect(sheet.style.transform).toBe('translate3d(0, 90px, 0)')
      // Back up during the same drag, and past the edge, where it stops rather than stretching.
      grip.dispatchEvent(gesture('pointermove', 230, 1_032))
      expect(sheet.style.transform).toBe('translate3d(0, 30px, 0)')
      grip.dispatchEvent(gesture('pointermove', 120, 1_048))
      expect(sheet.style.transform).toBe('translate3d(0, 0px, 0)')
      // Let go short of a dismissal: back where it sits at once, with nothing to wait for.
      grip.dispatchEvent(gesture('pointermove', 240, 1_064))
      grip.dispatchEvent(gesture('pointerup', 240, 1_400))
      expect(sheet.style.transform).toBe('translate3d(0, 0px, 0)')
      await waitFor(() => {
        expect(sheet).toHaveAttribute('data-presentation', 'here')
      })

      // A dismissal fades the surface where the finger left it.
      grip.dispatchEvent(gesture('pointerdown', 200, 2_000))
      grip.dispatchEvent(gesture('pointermove', 260, 2_016))
      grip.dispatchEvent(gesture('pointermove', 900, 2_032))
      grip.dispatchEvent(gesture('pointerup', 900, 2_048))
      await waitFor(() => {
        expect(sheet).toHaveAttribute('data-presentation', 'leaving')
      })
      expect(sheet.style.transform).toBe('translate3d(0, 700px, 0)')
      expect(sheet.style.opacity).toBe('0')
      await waitFor(() => {
        expect(screen.queryByTestId('sheet')).toBeNull()
      })
    } finally {
      vi.unstubAllGlobals()
    }
  })

  it('goes back where it sits when the platform cancels a drag, and a later movement moves nothing', async () => {
    start({ view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' })
    await userEvent.click(await screen.findByTestId('open-settings'))
    const sheet = await screen.findByTestId('sheet')
    await waitFor(() => {
      expect(sheet).toHaveAttribute('data-presentation', 'here')
    })
    const grip = screen.getByTestId('sheet-grip')
    grip.dispatchEvent(gesture('pointerdown', 200, 1_000))
    grip.dispatchEvent(gesture('pointermove', 260, 1_016))
    expect(sheet.style.transform).toBe('translate3d(0, 60px, 0)')
    grip.dispatchEvent(gesture('pointercancel', 260, 1_032))
    await waitFor(() => {
      expect(sheet.style.transform).toBe('translate3d(0, 0px, 0)')
    })
    await waitFor(() => {
      expect(sheet).toHaveAttribute('data-presentation', 'here')
    })
    // The drag is over: a movement after it belongs to no grab.
    grip.dispatchEvent(gesture('pointermove', 400, 1_048))
    expect(sheet.style.transform).toBe('translate3d(0, 0px, 0)')
  })

  it('dismisses on a downward flick', async () => {
    start({ view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' })
    await userEvent.click(await screen.findByTestId('open-settings'))
    const grip = await screen.findByTestId('sheet-grip')

    grip.dispatchEvent(new PointerEvent('pointerdown', { bubbles: true, clientY: 100 }))
    grip.dispatchEvent(new PointerEvent('pointermove', { bubbles: true, clientY: 160 }))
    grip.dispatchEvent(new PointerEvent('pointerup', { bubbles: true, clientY: 360 }))

    await waitFor(() => {
      expect(screen.queryByTestId('sheet')).toBeNull()
    })
  })

  // KR-REQ-25.08: answering a question is explained before a viewer can be given it.
  it('explains what answering means before a viewer can be given it', async () => {
    start({ view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' })
    await userEvent.click(await screen.findByTestId('open-settings'))
    await userEvent.click(await screen.findByRole('button', { name: 'Sharing' }))
    const explanation = await screen.findByTestId('answering-explanation')
    expect(explanation.textContent).toMatch(/input the agent may act on/)
    expect(explanation.textContent).toMatch(/A form does not reduce that/)
  })

  // KR-REQ-25.08: an invitation shows what it carries before it exists, and issues exactly that.
  it('shows what an invitation carries before it exists, and issues exactly that', async () => {
    const { controls } = start({ view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' })
    const person = userEvent.setup()
    await person.click(await screen.findByTestId('open-settings'))
    await person.click(await screen.findByRole('button', { name: 'Sharing' }))

    const carries = await screen.findByTestId('invitation-carries')
    await waitFor(() => {
      expect(carries.textContent).toContain('See what the session shows and does from when they accept')
    })
    expect(carries.querySelector('[data-notice]')).toBeNull()
    expect(within(carries).getByTestId('no-current-screen')).toHaveTextContent(
      'It does not include what is on the screen now'
    )

    // Letting a viewer answer questions is the authority the explanation names, and the host's own
    // sentence for it is shown before anything is issued.
    await person.click(screen.getByRole('switch', { name: 'Let a viewer or reviewer answer questions' }))
    await waitFor(() => {
      expect(carries.querySelector('[data-notice="agent_permissions"]')).not.toBeNull()
    })
    expect(carries.textContent).toContain('Answer the agent’s questions')

    // A device paired with this host is chosen, and a retired one is not offered.
    expect(screen.queryByRole('radio', { name: /Old phone/ })).toBeNull()
    await person.click(screen.getByRole('radio', { name: /Sam’s iPhone|Sam's iPhone/ }))
    await person.click(screen.getByTestId('invite'))

    expect(await screen.findByText(/Invitation issued to Sam's iPhone\. It is used once/)).toBeInTheDocument()
    const issued = await screen.findByTestId('issued-grants')
    expect(issued.textContent).toContain('Answer the agent’s questions')
    expect(within(issued).getByText('Waiting to be used')).toBeInTheDocument()
    expect(controls.records.agentOf(SESSION_MAIN).binding.binding_revision).toBe('4')
  })
})

describe('packages', () => {
  it('searches what the host holds without a network, and says so', async () => {
    start({ view: 'plugins' })
    expect(await screen.findByTestId('offline-search-note')).toBeInTheDocument()
    const installed = await screen.findByTestId('installed-list')
    await waitFor(() => {
      expect(within(installed).getByText('openai.codex')).toBeInTheDocument()
    })

    const search = screen.getByTestId('catalogue-search')
    await userEvent.type(search, 'tmux')
    expect(within(installed).getByText('community.tmux-status')).toBeInTheDocument()
    expect(within(installed).queryByText('openai.codex')).toBeNull()

    await userEvent.click(screen.getByRole('tab', { name: 'Catalogue' }))
    await userEvent.clear(search)
    await userEvent.type(search, 'mirror')
    const catalogues = screen.getByTestId('catalogue-list')
    expect(within(catalogues).getByText('community-mirror')).toBeInTheDocument()
    expect(within(catalogues).queryByText('official')).toBeNull()
  })

  it('says why new sessions leave a package out, and keeps a release still in use listed', async () => {
    start({ view: 'plugins' })
    const leftOut = await screen.findByTestId('left-out')
    expect(leftOut.textContent).toContain('community.tmux-status is disabled here')
    const live = await screen.findByTestId('live-releases')
    expect(live.textContent).toContain('openai.codex')
    expect(live.textContent).toContain('1.3.2')
    expect(within(live).getByText('Ending')).toBeInTheDocument()
  })

  it('shows repositories with their address, trust root, synchronisation and pin', async () => {
    start({ view: 'plugins' })
    await userEvent.click(await screen.findByRole('tab', { name: 'Repositories' }))
    const list = await screen.findByTestId('repository-list')
    await waitFor(() => {
      expect(within(list).getByText('https://packages.kala.to/metadata')).toBeInTheDocument()
    })
    expect(within(list).getByText('Pinned at 42')).toBeInTheDocument()
    expect(within(list).getByText(/not synchronised/)).toBeInTheDocument()
  })
})

describe('change sets', () => {
  it('shows what a change set holds and what it left out, and every version beside it', async () => {
    start({ view: 'changesets' })
    const shown = await screen.findByTestId('change-set')
    await waitFor(() => {
      expect(within(shown).getByRole('heading', { name: 'Wait on the subscription rather than a timer' })).toBeInTheDocument()
    })
    expect(shown.textContent).toContain('Version 2 of 2')
    expect(shown.textContent).toContain('Read while the workspace was held still.')
    expect(shown.textContent).toContain('tests/reconnect.rs')
    expect(shown.querySelector('[data-change="deleted"]')?.textContent).toContain('Deleted')
    expect(shown.textContent).toContain('Covered by a secret rule, so never read')
    expect(shown.textContent).toContain('Identical source does not reproduce')
  })

  it('reads each change set at the version its review names', async () => {
    const { port } = fakeHost()
    const asked: (string | null)[] = []
    render(
      <AppProvider
        port={{
          ...port,
          changesetRead: (params) => {
            asked.push(params.version)
            return port.changesetRead(params)
          }
        }}
        initialPlace={{ view: 'changesets' }}
      >
        <App />
      </AppProvider>
    )
    await screen.findByTestId('mark-reviewed')
    expect(asked).toEqual(['2'])
  })

  it('marks the version it shows reviewed, and says that approves nothing', async () => {
    start({ view: 'changesets' })
    const mark = await screen.findByTestId('mark-reviewed')
    expect(mark).toHaveTextContent('Mark version 2 reviewed')
    expect(screen.getByTestId('change-set').textContent).toContain('It approves nothing')
    await userEvent.click(mark)
    expect(await screen.findByText('Marked as reviewed.')).toBeInTheDocument()
    await waitFor(() => {
      expect(screen.queryByTestId('mark-reviewed')).toBeNull()
    })
  })
})

describe('retained artefacts', () => {
  it('shows what a privacy generation left behind, each with its own deletion', async () => {
    start({ view: 'changesets' })
    const retained = await screen.findByTestId('retained-artefacts')
    expect(within(retained).getByText(/Encrypted history archive/)).toBeInTheDocument()
    expect(within(retained).getByTestId('delete-obj-1')).toBeEnabled()
    expect(within(retained).getByText(/logical cleanup rather than a secure erase/)).toBeInTheDocument()
  })

  it('does not offer to delete a copy someone else holds', async () => {
    start({ view: 'changesets' })
    const retained = await screen.findByTestId('retained-artefacts')
    expect(within(retained).getByTestId('delete-obj-3')).toBeDisabled()
    expect(within(retained).getByTestId('held-elsewhere')).toBeInTheDocument()
  })

  it('deletes one artefact without touching the others', async () => {
    start({ view: 'changesets' })
    const retained = await screen.findByTestId('retained-artefacts')
    await userEvent.click(within(retained).getByTestId('delete-obj-1'))
    await waitFor(() => {
      expect(screen.queryByTestId('delete-obj-1')).toBeNull()
    })
    expect(screen.getByTestId('delete-obj-2')).toBeInTheDocument()
  })
})

describe('a control that commits on a completed action', () => {
  // KR-REQ-13.07: a press that ends outside the control is not a completed action.
  it('does not commit when the press slides off it', async () => {
    const commit = vi.fn()
    render(<CommitButton onCommit={commit}>Do it</CommitButton>)
    const button = screen.getByRole('button', { name: 'Do it' })
    vi.spyOn(button, 'getBoundingClientRect').mockReturnValue({
      left: 0,
      top: 0,
      right: 100,
      bottom: 40,
      width: 100,
      height: 40,
      x: 0,
      y: 0,
      toJSON: () => ({})
    })

    button.dispatchEvent(new PointerEvent('pointerdown', { bubbles: true, clientX: 50, clientY: 20 }))
    button.dispatchEvent(new PointerEvent('pointermove', { bubbles: true, clientX: 400, clientY: 20 }))
    button.dispatchEvent(new PointerEvent('pointerup', { bubbles: true, clientX: 400, clientY: 20 }))
    // The control holds the pointer's capture, so a browser sends it the click that follows the
    // release, wherever the release happened. That click belongs to the press that slid off.
    button.dispatchEvent(
      new MouseEvent('click', { bubbles: true, clientX: 400, clientY: 20, detail: 1 })
    )
    expect(commit).not.toHaveBeenCalled()
  })

  // KR-REQ-13.07: from the keyboard the action completes on key-up, once however long it is held.
  it('commits from the keyboard on key-up, and not once per repeat', async () => {
    for (const [held, released] of [
      ['{Enter>3}', '{/Enter}'],
      ['[Space>3]', '[/Space]']
    ] as const) {
      const commit = vi.fn()
      const person = userEvent.setup()
      const { unmount } = render(<CommitButton onCommit={commit}>Do it</CommitButton>)
      screen.getByRole('button', { name: 'Do it' }).focus()

      // Held down, and repeating: nothing is decided while the key is down.
      await person.keyboard(held)
      expect(commit).not.toHaveBeenCalled()
      // Released: the action completes, once.
      await person.keyboard(released)
      expect(commit).toHaveBeenCalledTimes(1)
      unmount()
    }
  })

  // KR-REQ-13.07: a commit from the keyboard, and a touch that slid off with no click after it,
  // leave nothing behind: the next click that counts no press, as WebKit's accessibility
  // activation sends, commits once each time.
  it('commits a click without a press after a key commit and after a touch that slid off', async () => {
    const commit = vi.fn()
    const person = userEvent.setup()
    render(<CommitButton onCommit={commit}>Do it</CommitButton>)
    const button = screen.getByRole('button', { name: 'Do it' })
    vi.spyOn(button, 'getBoundingClientRect').mockReturnValue({
      left: 0,
      top: 0,
      right: 100,
      bottom: 40,
      width: 100,
      height: 40,
      x: 0,
      y: 0,
      toJSON: () => ({})
    })
    const activate = (): void => {
      button.dispatchEvent(new MouseEvent('click', { bubbles: true, detail: 0 }))
    }

    button.focus()
    await person.keyboard('{Enter}')
    expect(commit).toHaveBeenCalledTimes(1)
    activate()
    expect(commit).toHaveBeenCalledTimes(2)

    // A touch that slides off decides nothing, and a browser sends no click after it.
    const touch = { bubbles: true, pointerType: 'touch', clientY: 20 }
    button.dispatchEvent(new PointerEvent('pointerdown', { ...touch, clientX: 50 }))
    button.dispatchEvent(new PointerEvent('pointermove', { ...touch, clientX: 400 }))
    button.dispatchEvent(new PointerEvent('pointerup', { ...touch, clientX: 400 }))
    expect(commit).toHaveBeenCalledTimes(2)
    activate()
    expect(commit).toHaveBeenCalledTimes(3)
  })

  // KR-REQ-13.07: assistive technology activates the control once in each engine the product runs
  // in. Chromium presses and releases the primary pointer at the control's centre and then clicks,
  // counting that press; WebKit sends a mouse press and release and a click that counts none. These
  // are the events each engine's accessibility activation dispatches, in order.
  it("commits once for each engine's accessibility activation", () => {
    const commit = vi.fn()
    render(<CommitButton onCommit={commit}>Do it</CommitButton>)
    const button = screen.getByRole('button', { name: 'Do it' })
    vi.spyOn(button, 'getBoundingClientRect').mockReturnValue({
      left: 0,
      top: 0,
      right: 100,
      bottom: 40,
      width: 100,
      height: 40,
      x: 0,
      y: 0,
      toJSON: () => ({})
    })
    const centre = { bubbles: true, cancelable: true, clientX: 50, clientY: 20, button: 0 }
    const mouse = { ...centre, pointerId: 1, pointerType: 'mouse', isPrimary: true }

    button.dispatchEvent(new PointerEvent('pointerdown', { ...mouse, buttons: 1 }))
    button.dispatchEvent(new MouseEvent('mousedown', { ...centre, buttons: 1 }))
    button.dispatchEvent(new PointerEvent('pointerup', mouse))
    button.dispatchEvent(new MouseEvent('mouseup', centre))
    button.dispatchEvent(new PointerEvent('click', { ...mouse, buttons: 1, detail: 1 }))
    expect(commit).toHaveBeenCalledTimes(1)

    button.dispatchEvent(new MouseEvent('mousedown', centre))
    button.dispatchEvent(new MouseEvent('mouseup', centre))
    button.dispatchEvent(new MouseEvent('click', { ...centre, detail: 0 }))
    expect(commit).toHaveBeenCalledTimes(2)
  })

  // KR-REQ-13.07: a pointer's press is decided by its release even when the engine takes focus
  // from the control on the press, as WebKit does with a button that had keyboard focus; losing
  // focus ends a key's press, whose key-up would arrive somewhere else.
  it('keeps a pointer press through a loss of focus, and ends a key press with it', async () => {
    const commit = vi.fn()
    const person = userEvent.setup()
    render(<CommitButton onCommit={commit}>Do it</CommitButton>)
    const button = screen.getByRole('button', { name: 'Do it' })
    const press = { bubbles: true, pointerId: 3, clientX: 0, clientY: 0 }

    button.focus()
    button.dispatchEvent(new PointerEvent('pointerdown', press))
    act(() => {
      button.blur()
    })
    button.dispatchEvent(new PointerEvent('pointerup', press))
    expect(commit).toHaveBeenCalledTimes(1)

    button.focus()
    await person.keyboard('{Enter>}')
    act(() => {
      button.blur()
    })
    button.focus()
    await person.keyboard('{/Enter}')
    expect(commit).toHaveBeenCalledTimes(1)
  })

  // KR-REQ-13.07: the pointer that pressed the control decides it. A second pointer's tap while
  // the first is held, and the click that tap brings, decide nothing; the first one's release does.
  it('is decided by the pointer that pressed it, not by a second one', async () => {
    const commit = vi.fn()
    const person = userEvent.setup()
    render(<CommitButton onCommit={commit}>Do it</CommitButton>)
    const button = screen.getByRole('button', { name: 'Do it' })
    const first = { bubbles: true, pointerId: 7, clientX: 0, clientY: 0 }

    button.dispatchEvent(new PointerEvent('pointerdown', first))
    await person.click(button)
    expect(commit).not.toHaveBeenCalled()
    button.dispatchEvent(new PointerEvent('pointerup', first))
    expect(commit).toHaveBeenCalledTimes(1)
  })
})

describe('one session at a time', () => {
  const SESSION_BUILD = '8a7b6c50-22bb-4c3d-8e4f-000000000102'

  it('keeps the draft when the view changes to the terminal and back', async () => {
    const { port } = fakeHost()
    const { rerender } = render(
      <AppProvider
        port={port}
        initialPlace={{ view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' }}
      >
        <App />
      </AppProvider>
    )
    await userEvent.type(await screen.findByTestId('composer-input'), 'half a thought')

    await userEvent.click(screen.getByRole('tab', { name: 'Terminal' }))
    await waitFor(() => {
      expect(screen.queryByTestId('composer-input')).toBeNull()
    })
    await userEvent.click(screen.getByRole('tab', { name: 'Conversation' }))

    expect(await screen.findByTestId('composer-input')).toHaveValue('half a thought')
    rerender(<div />)
  })

  it('does not show one session’s draft under another’s name', async () => {
    const { port } = fakeHost()
    render(
      <AppProvider
        port={port}
        initialPlace={{ view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' }}
      >
        <App />
      </AppProvider>
    )
    await userEvent.type(await screen.findByTestId('composer-input'), 'for the first session')

    // The same window, a different session: the tab strip is how a person moves between them.
    await userEvent.click(screen.getByRole('button', { name: 'Sessions' }))
    await userEvent.click(await screen.findByTestId('session-row-2'))

    expect(await screen.findByTestId('composer-input')).toHaveValue('')
  })

  it('ignores an event that belongs to another session', async () => {
    const { port, controls } = fakeHost()
    render(
      <AppProvider
        port={port}
        initialPlace={{ view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' }}
      >
        <App />
      </AppProvider>
    )
    await screen.findByTestId('conversation')

    // Addressed to the other session by hand. `appendNode` takes a session but publishes to the
    // main one whatever it is given, so an event that went through it would not be a foreign event
    // at all and this would be asserting nothing.
    controls.emit({
      stream_id: `semantic:${SESSION_BUILD}`,
      sequence: '1',
      body: {
        kind: 'node',
        node: {
          id: 'n-elsewhere',
          revision: '1',
          body: { kind: 'message', author: 'agent', text: 'this belongs to the build session' }
        }
      }
    })
    // A fence behind it: one node this session really does carry, published after the foreign one.
    // When the fence is on the screen everything queued in front of it has been drawn, so the
    // other session's text is missing because it was ignored rather than because the frame that
    // would have drawn it had not come round yet.
    controls.appendNode({
      id: 'n-here',
      revision: '1',
      body: { kind: 'message', author: 'agent', text: 'this one is for the session on screen' }
    } as never)

    await screen.findByText('this one is for the session on screen')
    expect(screen.queryByText('this belongs to the build session')).toBeNull()
  })

  it('gives the text back when the host refuses a submission', async () => {
    const { port } = fakeHost()
    const refusing = {
      ...port,
      composerSubmit: () =>
        Promise.reject({
          code: 'UPSTREAM_UNAVAILABLE',
          message: 'the agent is not reachable',
          user_action: 'wait'
        })
    }
    render(
      <AppProvider
        port={refusing}
        initialPlace={{ view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' }}
      >
        <App />
      </AppProvider>
    )
    const input = await screen.findByTestId('composer-input')
    await userEvent.type(input, 'do the thing')
    await userEvent.click(screen.getByTestId('composer-send'))

    await waitFor(() => {
      expect(screen.getByTestId('composer-input')).toHaveValue('do the thing')
    })
  })
})

describe('a refusal keeps what was written', () => {
  it('gives the text back when a later receipt refuses the submission', async () => {
    const { port, controls } = fakeHost()
    const action = '00000000-0000-4000-8000-00000000abcd'
    const pending: HostPort = {
      ...port,
      composerSubmit: (params) =>
        port.composerSubmit(params).then(() => ({
          // The host took the request and has not said what became of it yet.
          receipt: {
            action_id: action,
            actor_id: 'owner:local',
            error: null,
            method: 'agent.prompt.submit',
            method_version: 1,
            payload_digest: '0'.repeat(64),
            reason: null,
            revision: '1',
            state: 'accepted' as const,
            updated_at_ms: '0',
            accepted_deadline_ms: null
          },
          value: null,
          action_id: action
        }))
    }
    render(
      <AppProvider
        port={pending}
        initialPlace={{ view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' }}
      >
        <App />
      </AppProvider>
    )
    const input = await screen.findByTestId('composer-input')
    await userEvent.type(input, 'do the thing')
    await userEvent.click(screen.getByTestId('composer-send'))

    await waitFor(() => {
      expect(screen.getByTestId('composer-input')).toHaveValue('')
    })
    await screen.findByTestId('pending-actions')

    controls.emit({
      stream_id: `receipts:${SESSION_MAIN}`,
      sequence: '1',
      body: {
        kind: 'receipt',
        receipt: {
          action_id: action,
          state: 'refused',
          error: { code: 'UPSTREAM_UNAVAILABLE', message: 'the agent is not reachable' }
        }
      }
    })

    await waitFor(() => {
      expect(screen.getByTestId('composer-input')).toHaveValue('do the thing')
    })
  })
})
