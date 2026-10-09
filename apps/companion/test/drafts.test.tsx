/**
 * The composer's draft, kept on this device and never sent for the person (KR-REQ-13.13, 24.13).
 *
 * These render the real application against the scripted host, whose store of the device's drafts
 * applies the rules native code applies. A restart is a new render over the same store. Nothing a
 * test does here may send a prompt, and each one that could checks that nothing was.
 */

import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
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

describe('the drafts no composer shows (KR-REQ-13.13)', () => {
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
