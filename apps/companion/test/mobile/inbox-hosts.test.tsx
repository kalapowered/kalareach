/**
 * The attention inbox of a phone paired with more than one host, and with a host it cannot reach
 * (KR-REQ-13.01).
 *
 * The inbox is one across hosts and sessions. The host in use is read as ever; every other host this
 * phone is paired with is visited by native code and its rows are named by their host. A host that
 * does not answer is drawn as exactly that, with the rows it was last read to hold, and says nothing
 * of what its sessions are doing. The scripted host stands in for native code; the visits themselves
 * are proved against real hosts in the backend's own suite.
 */

import { act, cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it } from 'vitest'

import type { AttentionItem, AttentionReadResult } from '@kalareach/protocol'

import { AppProvider } from '../../src/app/state'
import { fakeHost, type FakeHostControls } from '../../src/host/fake'
import type { HostError, HostInbox, HostRow } from '../../src/host/port'
import { MobileApp } from '../../src/mobile/MobileApp'

afterEach(() => {
  cleanup()
})

const SESSION_MAIN = '8a7b6c50-22bb-4c3d-8e4f-000000000101'

const STUDIO: HostRow = {
  reference: 'studio-reference',
  in_use: true,
  name: 'studio',
  owner: false,
  authority: 'view sessions',
  grant_expires_at_ms: null,
  in_contact: null
}

const LAPTOP: HostRow = { ...STUDIO, reference: 'laptop-reference', in_use: false, name: 'laptop' }

/** An item a host's inbox holds. */
function item(over: Partial<AttentionItem> & Pick<AttentionItem, 'key' | 'rule'>): AttentionItem {
  const now = Date.now()
  return {
    source: 'semantic',
    level: 'notable',
    session_id: SESSION_MAIN,
    summary: null,
    trusted: true,
    routing: 'owner_policy',
    occurrences: '1',
    first_seen_ms: String(now - 90_000),
    last_seen_ms: String(now - 90_000),
    notification: 'delivered',
    awaiting_delivery: false,
    acknowledged: false,
    uncertain: false,
    revision: '1',
    automation: null,
    ...over
  }
}

function inboxOf(items: AttentionItem[]): AttentionReadResult {
  return {
    items,
    more: false,
    dropped: '0',
    gaps: [],
    quiet_hours: null,
    quiet_hours_provable: true,
    quiet_now: false
  }
}

/** What a visit finds of the laptop when it answers, holding one thing to review and one decision. */
function laptopRead(): HostInbox {
  return {
    reference: LAPTOP.reference,
    name: 'laptop',
    state: 'read',
    read_at_ms: Date.now(),
    lost_since_ms: null,
    refusal: null,
    result: inboxOf([
      item({
        key: 'attention.pending_approval|~laptop-1',
        rule: 'attention.pending_approval',
        level: 'urgent',
        summary: 'Claude asks to push the release branch'
      }),
      item({
        key: 'attention.review_ready|~laptop-2',
        rule: 'attention.review_ready',
        level: 'informational',
        summary: 'Three files changed on the laptop'
      })
    ]),
    sessions: [{ session_id: SESSION_MAIN, display_number: '7' }]
  }
}

function lostLaptop(sinceMs: number): HostInbox {
  return {
    reference: LAPTOP.reference,
    name: 'laptop',
    state: 'out_of_contact',
    read_at_ms: null,
    lost_since_ms: sinceMs,
    refusal: null,
    result: null,
    sessions: []
  }
}

/** What a visit finds of the laptop when it answers and refuses: the host is in contact. */
function refusingLaptop(refusal: HostError): HostInbox {
  return {
    reference: LAPTOP.reference,
    name: 'laptop',
    state: 'refused',
    read_at_ms: null,
    lost_since_ms: null,
    refusal,
    result: null,
    sessions: []
  }
}

function start(): { controls: FakeHostControls } {
  const { port, controls } = fakeHost()
  controls.setPairing({ hosts: [STUDIO, LAPTOP] })
  controls.setInboxHosts([laptopRead()])
  render(
    <AppProvider port={port}>
      <MobileApp surface="ios" storage={null} />
    </AppProvider>
  )
  return { controls }
}

/** The rows of the list, by the host each is from. */
function rowsOf(host: string): HTMLElement[] {
  return [...document.querySelectorAll<HTMLElement>(`[data-attention][data-host="${host}"]`)]
}

/** Has every cadence that reads while the page is shown read now. */
function readNow(): void {
  act(() => {
    document.dispatchEvent(new Event('visibilitychange'))
  })
}

describe('the inbox of a phone paired with two hosts', () => {
  it('lists the rows of the host in use and of the other, each named by its host', async () => {
    start()
    await waitFor(() => {
      expect(rowsOf('laptop')).toHaveLength(2)
    })
    expect(rowsOf('studio').length).toBeGreaterThan(0)
    const [decision] = rowsOf('laptop')
    expect(decision).toHaveTextContent('Claude asks to push the release branch')
    // The row says which host and which of its sessions, and the tab counts what waits on the person
    // on every host.
    expect(within(decision).getByText('laptop · Session 7')).toBeInTheDocument()
    expect(rowsOf('studio')[0]).toHaveTextContent(/studio · /)
  })

  // KR-REQ-13.01: an unreachable host is drawn as out of contact, never as failed.
  it('draws a host it cannot reach as out of contact, keeps the rows it last read, and says nothing of its sessions', async () => {
    const { controls } = start()
    await waitFor(() => {
      expect(rowsOf('laptop')).toHaveLength(2)
    })
    controls.setInboxHosts([lostLaptop(Date.now() - 5 * 60_000)])
    readNow()
    const contact = await screen.findByTestId('inbox-contact')
    expect(contact).toHaveAttribute('data-kind', 'disconnected')
    expect(contact).toHaveAttribute('data-host', 'laptop')
    expect(contact).toHaveTextContent('laptop is out of contact')
    expect(contact).toHaveTextContent('No contact for 5 minutes')
    expect(contact).toHaveTextContent('may still be running')
    // What it last held is still listed, said to be from the read before.
    expect(contact).toHaveTextContent(/was read .* ago/)
    expect(rowsOf('laptop')).toHaveLength(2)
    // It is counted as out of contact and not among the failures.
    expect(screen.getByRole('button', { name: /^Out of contact \(\d+\)$/ })).toBeInTheDocument()
    expect(contact).not.toHaveAttribute('data-kind', 'failed_action')
  })

  // KR-REQ-13.01: a host that answers and refuses is not out of contact. It is drawn as having
  // refused, in the host's words and with what the person can do, and is never counted as lost.
  it('draws a host that refused the visit as having refused, not as out of contact', async () => {
    const { controls } = start()
    await waitFor(() => {
      expect(rowsOf('laptop')).toHaveLength(2)
    })
    // The count of hosts out of contact, as it stands while the laptop answers: the host in use
    // lists one of its own.
    const outBefore = screen.getByRole('button', { name: /^Out of contact \(/ }).textContent
    controls.setInboxHosts([
      refusingLaptop({
        code: 'PERMISSION_DENIED',
        message: 'this device is no longer paired with this host',
        user_action: 'pair_again'
      })
    ])
    readNow()
    const refusal = await screen.findByTestId('inbox-refusal')
    expect(refusal).toHaveAttribute('data-kind', 'refused')
    expect(refusal).toHaveAttribute('data-host', 'laptop')
    expect(refusal).toHaveTextContent('laptop refused to show its inbox')
    // The host's own words, and what the person can do about them.
    expect(refusal).toHaveTextContent('this device is no longer paired with this host')
    expect(refusal).toHaveTextContent('Pair this device with the host again.')
    // The host answered: the row says so, and does not say that contact is gone.
    expect(refusal).not.toHaveTextContent(/No contact/)
    expect(screen.queryByTestId('inbox-contact')).toBeNull()
    expect(refusal).toHaveTextContent('may still be running')
    // Not counted as out of contact, and not among the failures. What the host held before it
    // refused is not listed: the host decided this phone is not shown its inbox.
    expect(screen.getByRole('button', { name: /^Out of contact \(/ }).textContent).toBe(outBefore)
    expect(refusal).not.toHaveAttribute('data-kind', 'failed_action')
    expect(rowsOf('laptop')).toHaveLength(0)
  })

  it('stops drawing the refusal once the host shows its inbox again', async () => {
    const { controls } = start()
    await waitFor(() => {
      expect(rowsOf('laptop')).toHaveLength(2)
    })
    controls.setInboxHosts([
      refusingLaptop({ code: 'PERMISSION_DENIED', message: 'not for this device', user_action: 'nothing' })
    ])
    readNow()
    await screen.findByTestId('inbox-refusal')
    controls.setInboxHosts([laptopRead()])
    readNow()
    await waitFor(() => {
      expect(screen.queryByTestId('inbox-refusal')).toBeNull()
    })
    expect(rowsOf('laptop')).toHaveLength(2)
  })

  it('draws the host in use as out of contact when it stops answering, and shows no generic failure', async () => {
    const { controls } = start()
    await waitFor(() => {
      expect(rowsOf('studio').length).toBeGreaterThan(0)
    })
    act(() => {
      controls.setConnected(false)
    })
    const contacts = await screen.findAllByTestId('inbox-contact')
    expect(contacts.map((each) => each.getAttribute('data-host'))).toContain('studio')
    const studio = contacts.find((each) => each.getAttribute('data-host') === 'studio')
    expect(studio).toHaveTextContent('studio is out of contact')
    expect(studio).toHaveTextContent(/^.*No contact/)
    expect(screen.queryByText('The inbox could not be read')).toBeNull()
    expect(rowsOf('studio').length).toBeGreaterThan(0)
  })

  it('shows nothing of the host that was in use once another is, whatever the new one answers', async () => {
    const { controls } = start()
    await waitFor(() => {
      expect(rowsOf('studio').length).toBeGreaterThan(0)
    })
    // The person chooses the laptop elsewhere, and it does not answer.
    act(() => {
      controls.setPairing({
        hosts: [
          { ...STUDIO, in_use: false },
          { ...LAPTOP, in_use: true }
        ]
      })
      controls.setConnected(false)
    })
    readNow()
    await waitFor(() => {
      expect(rowsOf('studio')).toHaveLength(0)
    })
    const contact = await screen.findByTestId('inbox-contact')
    expect(contact).toHaveAttribute('data-host', 'laptop')
  })

  // Nothing is claimed before the host in use has answered, whatever another host has.
  it('says it is reading until the host in use has answered, though another host has', async () => {
    const { port, controls } = fakeHost()
    controls.setPairing({ hosts: [STUDIO, LAPTOP] })
    controls.setInboxHosts([laptopRead()])
    const complete = controls.holdRegistrations()
    render(
      <AppProvider port={port}>
        <MobileApp surface="ios" storage={null} />
      </AppProvider>
    )
    await waitFor(() => {
      expect(rowsOf('laptop')).toHaveLength(2)
    })
    // The laptop's rows are listed, so the list is not empty; with them gone it would not say it is
    // empty either, since the host in use has not been heard.
    controls.setInboxHosts([{ ...laptopRead(), result: inboxOf([]), sessions: [] }])
    readNow()
    await waitFor(() => {
      expect(rowsOf('laptop')).toHaveLength(0)
    })
    expect(screen.getByText('Reading the inbox…')).toBeInTheDocument()
    expect(screen.queryByText(/Nothing needs you/)).toBeNull()
    complete()
  })

  it('lists the rows of the host in use as soon as the connection says which it is, not at the next round', async () => {
    const { port, controls } = fakeHost()
    render(
      <AppProvider port={port}>
        <MobileApp surface="ios" storage={null} />
      </AppProvider>
    )
    await act(async () => {
      await Promise.resolve()
    })
    act(() => {
      controls.reachAsPhone({ rights: ['session.view'] })
    })
    await waitFor(
      () => {
        expect(rowsOf('Studio').length).toBeGreaterThan(0)
      },
      { timeout: 2_000 }
    )
  })

  it('takes the other host into use before it opens one of its rows', async () => {
    const person = userEvent.setup()
    const { controls } = start()
    await waitFor(() => {
      expect(rowsOf('laptop')).toHaveLength(2)
    })
    const review = rowsOf('laptop')[1]
    expect(review).toHaveTextContent('Three files changed on the laptop')
    await person.click(review)
    await waitFor(() => {
      expect(controls.usedHosts).toEqual([LAPTOP.reference])
    })
    // The session opens on the host that is now in use.
    expect(await screen.findByRole('button', { name: 'Back to sessions' })).toBeInTheDocument()
  })
})
