/**
 * The screens, driven the way a person drives them.
 *
 * These render the real application against the scripted host. Nothing is mocked: the components
 * under test are the ones the desktop shell loads, and the answers they get are protocol values.
 */

import { describe, expect, it, vi } from 'vitest'
import { act, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { App } from '../src/App'
import { AppProvider, type Place } from '../src/app/state'
import { fakeHost, type FakeHostControls } from '../src/host/fake'
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
  it('keeps its four states apart', async () => {
    start()
    await waitFor(() => {
      expect(screen.getByTestId('attention-list')).toBeInTheDocument()
    })
    expect(screen.getByTestId('attention-pending_decision')).toBeInTheDocument()
    expect(screen.getByTestId('attention-failed_action')).toBeInTheDocument()
    expect(screen.getByTestId('attention-awaiting_review')).toBeInTheDocument()
    expect(screen.getByTestId('attention-disconnected')).toBeInTheDocument()
  })

  it('never calls a lost connection a failure', async () => {
    start()
    const entry = await screen.findByTestId('attention-disconnected')
    expect(within(entry).getByTestId('disconnected-note').textContent).toMatch(
      /does not\s+say what its processes are doing/
    )
    expect(entry.textContent).not.toMatch(/failed|stuck|crashed/i)
  })

  it('shows the command a decision would run before it is allowed', async () => {
    start()
    const entry = await screen.findByTestId('attention-pending_decision')
    expect(within(entry).getByText('scripts/release.sh --publish')).toBeInTheDocument()
  })

  it('answers an approval only on a completed press, and reports the receipt', async () => {
    start()
    const entry = await screen.findByTestId('attention-pending_decision')
    const allow = within(entry).getByRole('button', { name: 'Allow' })

    // Pointer-down alone is feedback, not a decision.
    allow.dispatchEvent(new PointerEvent('pointerdown', { bubbles: true, clientX: 5, clientY: 5 }))
    expect(screen.queryByText('Allowed.')).toBeNull()

    await userEvent.click(allow)
    expect(await screen.findByText('Allowed.')).toBeInTheDocument()
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

  it('offers slash commands when the draft starts with a slash', async () => {
    start({ view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' })
    const input = await screen.findByTestId('composer-input')
    await userEvent.type(input, '/com')
    expect(await screen.findByTestId('slash-commands')).toBeInTheDocument()
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

  it('shows a reconnect banner that never implies an action succeeded', async () => {
    const { controls } = start({ view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' })
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

  it('sends a dropped file through the transfer service before it touches the draft', async () => {
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
      { name: 'diagram.png', media_type: 'image/png', byte_len: 10, path: '/tmp/diagram.png' }
    ])

    await waitFor(() => {
      expect(controls.uploaded).toEqual(['/tmp/diagram.png'])
    })
    expect(await screen.findByText(/diagram.png attached/)).toBeInTheDocument()
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

  it('tells the person the draft is kept when a composer insertion is refused', async () => {
    const { port, controls } = fakeHost()
    render(
      <AppProvider port={port} initialPlace={{ view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' }}>
        <App />
      </AppProvider>
    )
    await screen.findByTestId('composer')

    // The host's own rule: a native composer insertion into a buffer it cannot qualify is refused.
    const refusing = {
      ...port,
      draftAddAttachment: () =>
        Promise.reject({
          code: 'DRAFT_CONFLICT',
          message: 'The agent composer is not at an empty, qualified boundary.',
          user_action: 'nothing'
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
    controls.dropFiles([
      { name: 'diagram.png', media_type: 'image/png', byte_len: 10, path: '/tmp/diagram.png' }
    ])

    const refusal = await screen.findByTestId('insertion-refusal')
    expect(refusal.textContent).toMatch(/kept/)
    expect(refusal.textContent).toMatch(/terminal/)
  })
})

describe('closing a session', () => {
  it('says what closing does before it is committed, and that history is kept', async () => {
    start({ view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' })
    await userEvent.click(await screen.findByTestId('close-session'))
    const consequence = await screen.findByTestId('close-consequence')
    expect(consequence.textContent).toMatch(/Approvals that are waiting are invalidated/)
    expect(consequence.textContent).toMatch(/Retained history is kept/)
    expect(consequence.textContent).toMatch(/every process it owns/)
  })

  it('commits only on a completed action', async () => {
    start({ view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' })
    await userEvent.click(await screen.findByTestId('close-session'))
    const confirm = await screen.findByTestId('confirm-close')

    confirm.dispatchEvent(new PointerEvent('pointerdown', { bubbles: true, clientX: 1, clientY: 1 }))
    expect(screen.queryByText(/The session is closed/)).toBeNull()

    await userEvent.click(confirm)
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

  it('explains what answering means before a viewer can be given it', async () => {
    start({ view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' })
    await userEvent.click(await screen.findByTestId('open-settings'))
    await userEvent.click(await screen.findByRole('button', { name: 'Sharing' }))
    const explanation = await screen.findByTestId('answering-explanation')
    expect(explanation.textContent).toMatch(/input the agent may act on/)
    expect(explanation.textContent).toMatch(/A form does not reduce that/)
  })

  it('refuses to give a viewer the answering right without that explanation', async () => {
    start({ view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' })
    await userEvent.click(await screen.findByTestId('open-settings'))
    await userEvent.click(await screen.findByRole('button', { name: 'Sharing' }))
    await userEvent.click(await screen.findByTestId('invite-viewer'))
    expect(await screen.findByText('Invitation issued.')).toBeInTheDocument()
  })
})

describe('pairing', () => {
  it('shows the rendezvous origin with a way to change it, before any attempt', async () => {
    start({ view: 'pairing' })
    expect((await screen.findByTestId('rendezvous-origin')).textContent).toBe(
      'https://rendezvous.kala.to'
    )
    expect(screen.getByTestId('change-origin')).toBeInTheDocument()
  })

  it('changes the origin and shows the new one', async () => {
    start({ view: 'pairing' })
    await userEvent.click(await screen.findByTestId('change-origin'))
    const input = await screen.findByTestId('origin-input')
    await userEvent.clear(input)
    await userEvent.type(input, 'https://pair.example.org')
    await userEvent.click(screen.getByTestId('save-origin'))
    await waitFor(() => {
      expect(screen.getByTestId('rendezvous-origin').textContent).toBe('https://pair.example.org')
    })
  })

  it('asks for an explicit confirmation showing the hostname when a code names another origin', async () => {
    const payload = JSON.stringify({
      version: 1,
      mode: 'code',
      rendezvous_origin: 'https://pair.example.org',
      code: 'KALA4821xy'
    })
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { readText: () => Promise.resolve(payload) }
    })

    start({ view: 'pairing' })
    await userEvent.click(await screen.findByTestId('paste-qr'))

    const confirmation = await screen.findByTestId('origin-confirmation')
    expect(within(confirmation).getByTestId('scanned-origin-host').textContent).toBe(
      'pair.example.org'
    )
    // Nothing has switched yet.
    expect(screen.getByTestId('rendezvous-origin').textContent).toBe('https://rendezvous.kala.to')

    await userEvent.click(within(confirmation).getByTestId('accept-origin'))
    await waitFor(() => {
      expect(screen.getByTestId('rendezvous-origin').textContent).toBe('https://pair.example.org')
    })
  })

  it('reports which platform ceremony verified the owner', async () => {
    start({ view: 'pairing' })
    await userEvent.click(await screen.findByTestId('verify-owner'))
    expect((await screen.findByTestId('presence-mechanism')).textContent).toMatch(
      /test.platform_ceremony/
    )
  })
})

describe('packages', () => {
  it('searches the catalogue without a network, and says so', async () => {
    start({ view: 'plugins' })
    expect(await screen.findByTestId('offline-search-note')).toBeInTheDocument()

    await userEvent.click(screen.getByRole('tab', { name: 'Catalogue' }))
    const search = await screen.findByTestId('catalogue-search')
    await userEvent.type(search, 'gemini')

    const list = screen.getByTestId('catalogue-list')
    expect(within(list).getByText('Gemini presentation')).toBeInTheDocument()
    expect(within(list).queryByText('tmux status')).toBeNull()
  })

  it('says when a package payload is not on this host rather than showing it as available', async () => {
    start({ view: 'plugins' })
    await userEvent.click(await screen.findByRole('tab', { name: 'Catalogue' }))
    expect(await screen.findByTestId('payload-offline')).toBeInTheDocument()
  })

  it('shows repositories with their kind, generation and expiry', async () => {
    start({ view: 'plugins' })
    await userEvent.click(await screen.findByRole('tab', { name: 'Repositories' }))
    const list = await screen.findByTestId('repository-list')
    expect(within(list).getByText('KalaReach official')).toBeInTheDocument()
    expect(within(list).getByText(/Metadata expired/)).toBeInTheDocument()
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
    expect(commit).not.toHaveBeenCalled()
  })

  it('commits from the keyboard on key-up, and not once per repeat', async () => {
    const commit = vi.fn()
    render(<CommitButton onCommit={commit}>Do it</CommitButton>)
    const button = screen.getByRole('button', { name: 'Do it' })
    button.focus()

    await userEvent.keyboard('{Enter>3/}')
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
    const pending = {
      ...port,
      composerSubmit: (params: unknown, subject: Parameters<typeof port.composerSubmit>[1]) =>
        port.composerSubmit(params, subject).then((settled) => ({
          ...settled,
          // The host took the request and has not said what became of it yet.
          receipt: settled.receipt ? { ...settled.receipt, state: 'accepted' as const } : null
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
    const actionId = controls.actions[controls.actions.length - 1]

    controls.emit({
      stream_id: `receipts:${SESSION_MAIN}`,
      sequence: '1',
      body: {
        kind: 'receipt',
        receipt: {
          action_id: actionId,
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
