/**
 * The phone keeps a draft on the device as it is typed, and lists the drafts no composer shows
 * (KR-REQ-13.13, 24.13).
 *
 * The recovery cases of a draft that comes back through a suspension or a restart are in
 * `recovery.test.tsx`; these are what the device's own store adds: the composer waits for it, a
 * draft its session no longer has is listed rather than lost, and a person reaches the list from the
 * sessions and from the banner that reports the recovery.
 */

import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it } from 'vitest'

import { AppProvider } from '../../src/app/state'
import { fakeHost } from '../../src/host/fake'
import { FakeDraftStore } from '../../src/host/fake-drafts'
import type { HostPort } from '../../src/host/port'
import { MobileApp } from '../../src/mobile/MobileApp'

const SESSION_MAIN = '8a7b6c50-22bb-4c3d-8e4f-000000000101'
const GONE = 'aaaaaaaa-aaaa-4aaa-8aaa-00000000dead'

afterEach(cleanup)

function leave(device: FakeDraftStore, sessionId: string, text: string, state: 'open' | 'orphaned' = 'open') {
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

function open(device: FakeDraftStore, wrap?: (port: HostPort) => HostPort) {
  const host = fakeHost({ drafts: device })
  render(
    <AppProvider port={wrap ? wrap(host.port) : host.port}>
      <MobileApp surface="ios" storage={null} />
    </AppProvider>
  )
  return host
}

describe('the phone’s composer and the device’s store (KR-REQ-13.13)', () => {
  it('shows the draft that was kept, once the store has been read, and not an empty field before', async () => {
    const device = new FakeDraftStore()
    leave(device, SESSION_MAIN, 'written yesterday')
    let release: () => void = () => undefined
    const gate = new Promise<void>((resolve) => {
      release = resolve
    })
    const person = userEvent.setup()
    open(device, (port) => ({
      ...port,
      deviceDrafts: async () => {
        await gate
        return await port.deviceDrafts()
      }
    }))
    await person.click(await screen.findByRole('button', { name: /^Sessions/ }))
    await person.click(await screen.findByRole('button', { name: /Session 1/ }))
    expect(await screen.findByText('Opening your drafts…')).toBeInTheDocument()
    expect(screen.queryByRole('textbox', { name: 'Message this session' })).toBeNull()

    release()
    expect(await screen.findByLabelText('Message this session')).toHaveValue('written yesterday')
  })

  it('says so when the device will not keep drafts', async () => {
    const device = new FakeDraftStore()
    device.breakOpening()
    const person = userEvent.setup()
    open(device)
    await person.click(await screen.findByRole('button', { name: /^Sessions/ }))
    await person.click(await screen.findByRole('button', { name: /Session 1/ }))
    await person.type(await screen.findByLabelText('Message this session'), 'typed anyway')
    expect(screen.getByText('This device will not keep what you write')).toBeInTheDocument()
    expect(screen.getByLabelText('Message this session')).toHaveValue('typed anyway')
  })
})

describe('a phone whose drafts could not be opened', () => {
  it('opens them again when the person asks, and keeps what was typed meanwhile', async () => {
    const device = new FakeDraftStore()
    device.breakOpening()
    const person = userEvent.setup()
    open(device)
    await person.click(await screen.findByRole('button', { name: /^Sessions/ }))
    await person.click(await screen.findByRole('button', { name: /Session 1/ }))
    await person.type(await screen.findByLabelText('Message this session'), 'typed meanwhile')
    expect(screen.getByText('This device will not keep what you write')).toBeInTheDocument()

    device.mendOpening()
    await person.click(screen.getByTestId('drafts-retry'))
    await waitFor(() => {
      expect(screen.queryByText('This device will not keep what you write')).toBeNull()
    })
    await waitFor(() => {
      expect(device.all().map((draft) => draft.text)).toEqual(['typed meanwhile'])
    })
    expect(screen.getByLabelText('Message this session')).toHaveValue('typed meanwhile')
  })
})

describe('the drafts no composer shows, on a phone (KR-REQ-13.13)', () => {
  it('says so when some drafts could not be read, and has the entry for it', async () => {
    const device = new FakeDraftStore()
    device.leaveUnreadable(2)
    const person = userEvent.setup()
    open(device)
    await person.click(await screen.findByRole('button', { name: /^Sessions/ }))
    await person.click(await screen.findByTestId('kept-drafts-entry'))
    expect(await screen.findByText('Some drafts could not be read')).toBeInTheDocument()
    expect(screen.getByText(/2 stored drafts could not be read/)).toBeInTheDocument()
  })

  it('are reached from the sessions, and listed with what became of their session', async () => {
    const device = new FakeDraftStore()
    leave(device, GONE, 'for a session that went', 'orphaned')
    const person = userEvent.setup()
    open(device)
    await person.click(await screen.findByRole('button', { name: /^Sessions/ }))
    await person.click(await screen.findByTestId('kept-drafts-entry'))

    const entry = await screen.findByTestId('kept-draft')
    expect(within(entry).getByTestId('kept-draft-why')).toHaveTextContent('has gone')
    expect(within(entry).getByTestId('kept-draft-text')).toHaveTextContent('for a session that went')
    // The bar names the screen and leaves it.
    await person.click(screen.getByRole('button', { name: 'Back to sessions' }))
    expect(await screen.findByRole('button', { name: /Session 1/ })).toBeInTheDocument()
  })

  it('moves one to a session the person chooses, and then shows it in that session’s composer', async () => {
    const device = new FakeDraftStore()
    leave(device, GONE, 'for a session that went', 'orphaned')
    const person = userEvent.setup()
    open(device)
    await person.click(await screen.findByRole('button', { name: /^Sessions/ }))
    await person.click(await screen.findByTestId('kept-drafts-entry'))
    const entry = await screen.findByTestId('kept-draft')
    await waitFor(() => {
      expect(within(entry).getByTestId('kept-draft-session')).toBeEnabled()
    })
    await person.selectOptions(within(entry).getByTestId('kept-draft-session'), SESSION_MAIN)
    await person.click(within(entry).getByTestId('kept-draft-move'))
    await waitFor(() => {
      expect(screen.getByTestId('kept-drafts-empty')).toBeInTheDocument()
    })

    await person.click(screen.getByRole('button', { name: 'Back to sessions' }))
    await person.click(await screen.findByRole('button', { name: /Session 1/ }))
    expect(await screen.findByLabelText('Message this session')).toHaveValue('for a session that went')
  })

  it('has no entry in the sessions while nothing is kept apart', async () => {
    const person = userEvent.setup()
    open(new FakeDraftStore())
    await person.click(await screen.findByRole('button', { name: /^Sessions/ }))
    await screen.findByRole('button', { name: /Session 1/ })
    expect(screen.queryByTestId('kept-drafts-entry')).toBeNull()
  })
})
