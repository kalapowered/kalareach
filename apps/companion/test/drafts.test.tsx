/**
 * The composer's draft, kept on this device and never sent for the person (KR-REQ-13.13, 24.13).
 *
 * These render the real application against the scripted host, whose store of the device's drafts
 * applies the rules native code applies. A restart is a new render over the same store. Nothing a
 * test does here may send a prompt, and each one that could checks that nothing was.
 */

import { act, cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it } from 'vitest'

import { App } from '../src/App'
import { AppProvider, type Place } from '../src/app/state'
import { fakeHost } from '../src/host/fake'
import { FakeDraftStore } from '../src/host/fake-drafts'
import type { HostPort } from '../src/host/port'

const SESSION_MAIN = '8a7b6c50-22bb-4c3d-8e4f-000000000101'
const SESSION_BUILD = '8a7b6c50-22bb-4c3d-8e4f-000000000102'
const IN_MAIN: Place = { view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' }

afterEach(cleanup)

/** The application started over a device's store of drafts. */
function startOver(device: FakeDraftStore, place: Place = IN_MAIN, wrap?: (port: HostPort) => HostPort) {
  const host = fakeHost({ drafts: device })
  const view = render(
    <AppProvider port={wrap ? wrap(host.port) : host.port} initialPlace={place}>
      <App />
    </AppProvider>
  )
  return { ...host, view }
}

/** A stored draft for a session, as an earlier run of the application left it. */
function leave(device: FakeDraftStore, sessionId: string, text: string, state: 'open' | 'orphaned' | 'conflicted' = 'open') {
  return device.save({
    id: null,
    expectedRevision: null,
    sessionId,
    applicationInstanceId: null,
    agentBindingRevision: null,
    state,
    text,
    attachments: []
  }).draft
}

describe('a draft is kept on this device as it is typed (KR-REQ-13.13, 24.13)', () => {
  it('is still there when the application starts again, and nothing was sent to bring it back', async () => {
    const device = new FakeDraftStore()
    const person = userEvent.setup()
    const first = startOver(device)
    await person.type(await screen.findByTestId('composer-input'), 'half a thought')
    await waitFor(() => {
      expect(device.all().map((draft) => draft.text)).toEqual(['half a thought'])
    })
    first.view.unmount()

    const second = startOver(device)
    expect(await screen.findByTestId('composer-input')).toHaveValue('half a thought')
    // The host is reached, so the draft is bound to its conversation again; it is not sent.
    await waitFor(() => {
      expect(screen.getByTestId('composer-send')).toBeEnabled()
    })
    expect(second.controls.submissions).toBe(0)
    expect(second.controls.actions).toEqual([])
  })

  it('is there after the session’s tab is closed and the session is opened again', async () => {
    const device = new FakeDraftStore()
    const person = userEvent.setup()
    startOver(device)
    await person.type(await screen.findByTestId('composer-input'), 'kept past the tab')
    // Both sessions' tabs open, which makes the strip of tabs appear.
    await person.click(screen.getByRole('button', { name: 'Sessions' }))
    await person.click(await screen.findByTestId('session-row-1'))
    await person.click(screen.getByRole('button', { name: 'Sessions' }))
    await person.click(await screen.findByTestId('session-row-2'))
    await person.click(await screen.findByRole('button', { name: 'Close the tab for session 01' }))
    await person.click(screen.getByRole('button', { name: 'Sessions' }))
    await person.click(await screen.findByTestId('session-row-1'))
    expect(await screen.findByTestId('composer-input')).toHaveValue('kept past the tab')
  })

  it('waits for the kept drafts to be read, and shows them rather than an empty field', async () => {
    const device = new FakeDraftStore()
    leave(device, SESSION_MAIN, 'written yesterday')
    let release: () => void = () => undefined
    const gate = new Promise<void>((resolve) => {
      release = resolve
    })
    startOver(device, IN_MAIN, (port) => ({
      ...port,
      deviceDrafts: async () => {
        await gate
        return await port.deviceDrafts()
      }
    }))
    // Until the store has been read, a keystroke would be typed over what is kept: there is no field.
    expect(await screen.findByText('Opening your drafts…')).toBeInTheDocument()
    expect(screen.queryByTestId('composer-input')).toBeNull()

    release()
    expect(await screen.findByTestId('composer-input')).toHaveValue('written yesterday')
  })

  it('says so when the device will not keep drafts, and keeps what is typed in the window', async () => {
    const device = new FakeDraftStore()
    device.breakOpening()
    const person = userEvent.setup()
    startOver(device)
    await person.type(await screen.findByTestId('composer-input'), 'typed anyway')
    expect(await screen.findByTestId('drafts-not-kept')).toHaveTextContent(/not keeping what you write/)
    expect(screen.getByTestId('composer-input')).toHaveValue('typed anyway')
  })

  it('keeps this window’s text beside another window’s version, and says so', async () => {
    const device = new FakeDraftStore()
    const person = userEvent.setup()
    startOver(device)
    await person.type(await screen.findByTestId('composer-input'), 'begun here')
    await waitFor(() => {
      expect(device.all()).toHaveLength(1)
    })
    // Another window of the application changes the same draft.
    device.writeAsAnotherWindow(device.all()[0]?.id ?? '', { text: 'the other window’s version' })

    await person.type(screen.getByTestId('composer-input'), ' and more')
    expect(await screen.findByText(/Another window of this application changed that draft/)).toBeInTheDocument()
    await waitFor(() => {
      expect(device.all().map((draft) => draft.text).sort()).toEqual([
        'begun here and more',
        'the other window’s version'
      ])
    })
    expect(screen.getByTestId('composer-input')).toHaveValue('begun here and more')
  })
})

describe('a prompt from a draft leaves the stored draft until the host took it (KR-REQ-13.13)', () => {
  it('removes it once the host took the prompt, and names no draft in the prompt', async () => {
    const device = new FakeDraftStore()
    const person = userEvent.setup()
    const sent: (string | null)[] = []
    startOver(device, IN_MAIN, (port) => ({
      ...port,
      composerSubmit: (params) => {
        sent.push(params.draft_id)
        return port.composerSubmit(params)
      }
    }))
    await person.type(await screen.findByTestId('composer-input'), 'send this')
    await waitFor(() => {
      expect(screen.getByTestId('composer-send')).toBeEnabled()
    })
    await waitFor(() => {
      expect(device.all()).toHaveLength(1)
    })
    await person.click(screen.getByTestId('composer-send'))

    await waitFor(() => {
      expect(device.all()).toEqual([])
    })
    expect(sent).toEqual([null])
    expect(screen.getByTestId('composer-input')).toHaveValue('')
  })

  it('keeps it, and gives the text back, when the host refused the prompt', async () => {
    const device = new FakeDraftStore()
    const person = userEvent.setup()
    startOver(device, IN_MAIN, (port) => ({
      ...port,
      composerSubmit: () =>
        Promise.reject({ code: 'UNAVAILABLE', message: 'The host did not answer.', user_action: 'retry' })
    }))
    await person.type(await screen.findByTestId('composer-input'), 'send this too')
    await waitFor(() => {
      expect(screen.getByTestId('composer-send')).toBeEnabled()
    })
    await person.click(screen.getByTestId('composer-send'))

    await waitFor(() => {
      expect(screen.getByTestId('composer-input')).toHaveValue('send this too')
    })
    expect(device.all().map((draft) => draft.text)).toEqual(['send this too'])
  })
})

/** A host answer a test settles when it chooses, for a prompt that is on its way. */
function held<T>(): { promise: Promise<T>; resolve: (value: T) => void; reject: (reason: unknown) => void } {
  let resolve: (value: T) => void = () => undefined
  let reject: (reason: unknown) => void = () => undefined
  const promise = new Promise<T>((accept, refuse) => {
    resolve = accept
    reject = refuse
  })
  return { promise, resolve, reject }
}

describe('a prompt the host did not take, and the text it was sent from (KR-REQ-13.13, 24.13)', () => {
  it('keeps what was sent and what was written meanwhile, and the person finds the first in the kept drafts', async () => {
    const device = new FakeDraftStore()
    const person = userEvent.setup()
    const answer = held<never>()
    startOver(device, IN_MAIN, (port) => ({
      ...port,
      composerSubmit: () => answer.promise
    }))
    await person.type(await screen.findByTestId('composer-input'), 'send this')
    await waitFor(() => {
      expect(screen.getByTestId('composer-send')).toBeEnabled()
    })
    await person.click(screen.getByTestId('composer-send'))
    // The composer is empty and the person writes the next thing while the prompt is on its way.
    await person.type(screen.getByTestId('composer-input'), 'the next thing')
    answer.reject({ code: 'UNAVAILABLE', message: 'The host did not answer.', user_action: 'retry' })

    await waitFor(() => {
      expect(device.all().map((draft) => draft.text).sort()).toEqual(['send this', 'the next thing'])
    })
    expect(screen.getByTestId('composer-input')).toHaveValue('the next thing')
    await person.click(screen.getByRole('button', { name: 'Sessions' }))
    await person.click(await screen.findByRole('button', { name: 'One kept draft' }))
    expect(await screen.findByTestId('kept-draft-text')).toHaveTextContent('send this')
  })

  it('keeps the text of a prompt whose outcome nobody knows, and the text written meanwhile beside it', async () => {
    const device = new FakeDraftStore()
    const person = userEvent.setup()
    const answer = held<{ receipt: null; value: null; action_id: null }>()
    startOver(device, IN_MAIN, (port) => ({
      ...port,
      // The host answers with neither a receipt nor a result: what became of the prompt is unknown.
      composerSubmit: () => answer.promise
    }))
    await person.type(await screen.findByTestId('composer-input'), 'send this')
    await waitFor(() => {
      expect(screen.getByTestId('composer-send')).toBeEnabled()
    })
    await person.click(screen.getByTestId('composer-send'))
    await person.type(screen.getByTestId('composer-input'), 'the next thing')
    answer.resolve({ receipt: null, value: null, action_id: null })

    await waitFor(() => {
      expect(device.all().map((draft) => draft.text).sort()).toEqual(['send this', 'the next thing'])
    })
    expect(screen.getByTestId('composer-input')).toHaveValue('the next thing')
  })

  it('writes again what the store refused when the page is hidden', async () => {
    const device = new FakeDraftStore()
    const person = userEvent.setup()
    startOver(device)
    device.refuseSaves({ code: 'STORAGE_UNAVAILABLE', message: 'the disk is full' })
    await person.type(await screen.findByTestId('composer-input'), 'written while the disk was full')
    await waitFor(() => {
      expect(screen.getByTestId('drafts-not-kept')).toBeInTheDocument()
    })
    expect(device.all()).toEqual([])

    device.refuseSaves(null)
    act(() => {
      window.dispatchEvent(new Event('pagehide'))
    })
    await waitFor(() => {
      expect(device.all().map((draft) => draft.text)).toEqual(['written while the disk was full'])
    })
  })

  it('gives the text back when the tab it was sent from was closed before the answer', async () => {
    const device = new FakeDraftStore()
    const person = userEvent.setup()
    const answer = held<never>()
    startOver(device, IN_MAIN, (port) => ({
      ...port,
      composerSubmit: () => answer.promise
    }))
    await person.type(await screen.findByTestId('composer-input'), 'sent from a tab that closed')
    await waitFor(() => {
      expect(screen.getByTestId('composer-send')).toBeEnabled()
    })
    await person.click(screen.getByTestId('composer-send'))
    // The strip of tabs shows with two open, and the person closes the one the prompt came from.
    await person.click(screen.getByRole('button', { name: 'Sessions' }))
    await person.click(await screen.findByTestId('session-row-1'))
    await person.click(screen.getByRole('button', { name: 'Sessions' }))
    await person.click(await screen.findByTestId('session-row-2'))
    await person.click(await screen.findByRole('button', { name: 'Close the tab for session 01' }))
    answer.reject({ code: 'UNAVAILABLE', message: 'The host did not answer.', user_action: 'retry' })

    await waitFor(() => {
      expect(device.all().map((draft) => draft.text)).toEqual(['sent from a tab that closed'])
    })
    await person.click(screen.getByRole('button', { name: 'Sessions' }))
    await person.click(await screen.findByTestId('session-row-1'))
    expect(await screen.findByTestId('composer-input')).toHaveValue('sent from a tab that closed')
  })
})

describe('the drafts no composer shows (KR-REQ-13.13)', () => {
  it('says "is" of one kept draft and "are" of several', async () => {
    const device = new FakeDraftStore()
    leave(device, 'aaaaaaaa-aaaa-4aaa-8aaa-00000000dead', 'one', 'orphaned')
    startOver(device, { view: 'sessions' })
    expect(await screen.findByTestId('kept-drafts-entry')).toHaveTextContent('One kept draft is not in a composer.')
  })

  it('puts a copy in its own session’s composer, and keeps what the composer held beside it', async () => {
    const device = new FakeDraftStore()
    const theirs = leave(device, SESSION_MAIN, 'theirs')
    // A save of an older version is kept beside: this is another window's text, as a copy.
    device.save({
      id: theirs.id,
      expectedRevision: '0',
      sessionId: SESSION_MAIN,
      applicationInstanceId: null,
      agentBindingRevision: null,
      state: 'open',
      text: 'mine',
      attachments: []
    })
    const person = userEvent.setup()
    startOver(device, { view: 'drafts' })

    const entry = await screen.findByTestId('kept-draft')
    expect(within(entry).getByTestId('kept-draft-text')).toHaveTextContent('mine')
    await waitFor(() => {
      expect(within(entry).getByTestId('kept-draft-use')).toBeEnabled()
    })
    await person.click(within(entry).getByTestId('kept-draft-use'))
    // Theirs stays kept, and is now the one listed apart.
    await waitFor(() => {
      expect(screen.getByTestId('kept-draft-text')).toHaveTextContent('theirs')
    })
    expect(device.all().map((draft) => draft.text).sort()).toEqual(['mine', 'theirs'])
  })

  it('lists and discards a draft with no host to ask, and says it cannot offer a session to move it to', async () => {
    const device = new FakeDraftStore()
    leave(device, 'aaaaaaaa-aaaa-4aaa-8aaa-00000000dead', 'for a session that went', 'orphaned')
    const person = userEvent.setup()
    startOver(device, { view: 'drafts' }, (port) => ({
      ...port,
      sessionList: () => Promise.reject({ code: 'UNAVAILABLE', message: 'No host.', user_action: 'retry' })
    }))
    const entry = await screen.findByTestId('kept-draft')
    expect(await screen.findByTestId('kept-drafts-offline')).toBeInTheDocument()
    expect(within(entry).queryByTestId('kept-draft-session')).toBeNull()
    expect(within(entry).queryByTestId('kept-draft-use')).toBeNull()

    await person.click(within(entry).getByTestId('kept-draft-discard'))
    await waitFor(() => {
      expect(device.all()).toEqual([])
    })
  })

  it('says so when some drafts could not be read, and does not call the list empty without saying why', async () => {
    const device = new FakeDraftStore()
    device.leaveUnreadable(1)
    const person = userEvent.setup()
    startOver(device, { view: 'sessions' })
    await person.click(await screen.findByRole('button', { name: 'Some drafts' }))
    expect(await screen.findByText('Some drafts could not be read')).toBeInTheDocument()
    expect(screen.getByText(/One stored draft could not be read/)).toBeInTheDocument()
  })

  it('opens the store again when the person asks', async () => {
    const device = new FakeDraftStore()
    device.breakOpening()
    const person = userEvent.setup()
    startOver(device, { view: 'drafts' })
    expect(await screen.findByText('This device is not keeping drafts')).toBeInTheDocument()
    device.mendOpening()
    await person.click(screen.getByTestId('kept-drafts-retry'))
    await waitFor(() => {
      expect(screen.queryByText('This device is not keeping drafts')).toBeNull()
    })
  })

  it('lists a draft whose session has gone, and moves it to a session the person chooses', async () => {
    const device = new FakeDraftStore()
    leave(device, 'aaaaaaaa-aaaa-4aaa-8aaa-00000000dead', 'for a session that went', 'orphaned')
    const person = userEvent.setup()
    startOver(device, { view: 'sessions' })

    await person.click(await screen.findByRole('button', { name: 'One kept draft' }))
    const entry = await screen.findByTestId('kept-draft')
    expect(within(entry).getByTestId('kept-draft-why')).toHaveTextContent('has gone')
    expect(within(entry).getByTestId('kept-draft-text')).toHaveTextContent('for a session that went')

    await waitFor(() => {
      expect(within(entry).getByTestId('kept-draft-session')).toBeEnabled()
    })
    await person.selectOptions(within(entry).getByTestId('kept-draft-session'), SESSION_BUILD)
    await person.click(within(entry).getByTestId('kept-draft-move'))
    await waitFor(() => {
      expect(screen.getByTestId('kept-drafts-empty')).toBeInTheDocument()
    })
    expect(device.all()[0]).toMatchObject({ sessionId: SESSION_BUILD, state: 'open' })
  })

  it('discards a kept draft only on a completed press, and then nothing of it is kept', async () => {
    const device = new FakeDraftStore()
    leave(device, 'aaaaaaaa-aaaa-4aaa-8aaa-00000000dead', 'not wanted any more', 'orphaned')
    const person = userEvent.setup()
    startOver(device, { view: 'drafts' })
    const entry = await screen.findByTestId('kept-draft')
    await person.click(within(entry).getByTestId('kept-draft-discard'))
    await waitFor(() => {
      expect(device.all()).toEqual([])
    })
    expect(await screen.findByTestId('kept-drafts-empty')).toBeInTheDocument()
  })

  it('offers no way in when nothing is kept apart', async () => {
    const device = new FakeDraftStore()
    startOver(device, { view: 'sessions' })
    await screen.findByTestId('session-row-1')
    expect(screen.queryByTestId('kept-drafts-entry')).toBeNull()
  })
})
