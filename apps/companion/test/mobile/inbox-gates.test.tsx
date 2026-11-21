/**
 * What the mobile inbox shows, and when: every row is derived from the connection's latest state,
 * and a cache is shown only under the owner's key (KR-REQ-13.01, KR-REQ-13.02).
 *
 * The scripted host stands in for native code. A case holds the reads it needs to order and answers
 * them by index, or holds the connection's publications, so what decides each outcome is the order
 * of the calls and never the time a call takes. The one case that depends on a clock sets it.
 */

import { act, cleanup, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'

import type { AttentionItem, AttentionReadResult } from '@kalareach/protocol'

import { AppProvider } from '../../src/app/state'
import { fakeHost, type FakeHostControls, type HeldReads } from '../../src/host/fake'
import type {
  ConnectionState,
  HostContact,
  HostError,
  HostInbox,
  HostPort,
  HostRow,
  OtherHost
} from '../../src/host/port'
import { receivedFailure } from '../../src/host/tauri'
import { MobileApp } from '../../src/mobile/MobileApp'

afterEach(() => {
  cleanup()
  vi.useRealTimers()
})

const SESSION = '8a7b6c50-22bb-4c3d-8e4f-000000000101'

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

const REFUSAL: HostError = receivedFailure({
  code: 'PERMISSION_DENIED',
  message: 'this device may not read this host',
  user_action: 'fix_configuration',
  retry: 'configuration_change'
})

function item(key: string, summary: string): AttentionItem {
  const now = Date.now()
  return {
    key,
    rule: 'attention.review_ready',
    source: 'semantic',
    level: 'informational',
    session_id: SESSION,
    summary,
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
    automation: null
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

/** What a pass holds of the laptop: one item named `summary`, read under `epoch` as the `serial`th read. */
function laptopRow(epoch: number, serial: number, summary: string): HostInbox {
  return {
    reference: LAPTOP.reference,
    name: 'laptop',
    inbox_epoch: epoch,
    read_serial: serial,
    read_at_ms: Date.now(),
    result: inboxOf([item(`attention.review_ready|~${summary}`, summary)]),
    sessions: [{ session_id: SESSION, display_number: '7' }]
  }
}

function laptopOther(epoch: number, contact: HostContact = { state: 'in_contact' }): OtherHost {
  return { reference: LAPTOP.reference, name: 'laptop', contact, inbox_epoch: epoch }
}

interface Started {
  readonly controls: FakeHostControls
  readonly port: HostPort
}

/**
 * A phone paired with the studio, which is in use, and with the laptop. The connection's state names
 * the studio, so what the page shows of it is the state's. `others` is what a pass finds of the laptop.
 */
function start(
  others: { readonly row: HostInbox; readonly other: OtherHost } | null = {
    row: laptopRow(3, 7, 'laptop first'),
    other: laptopOther(3)
  },
  before: (controls: FakeHostControls) => void = () => undefined
): Started {
  const { port, controls } = fakeHost()
  controls.setPairing({ hosts: [STUDIO, LAPTOP] })
  controls.setHostInUse({ kind: 'paired', reference: STUDIO.reference, name: 'studio' })
  controls.setInboxHosts(others === null ? [] : [others.row])
  controls.setOtherHosts(others === null ? [] : [others.other])
  before(controls)
  render(
    <AppProvider port={port}>
      <MobileApp surface="ios" storage={null} />
    </AppProvider>
  )
  return { controls, port }
}

function rowsOf(host: string): HTMLElement[] {
  return [...document.querySelectorAll<HTMLElement>(`[data-attention][data-host="${host}"]`)]
}

/** Has every cadence that reads while the page is shown read now. */
function readNow(): void {
  act(() => {
    document.dispatchEvent(new Event('visibilitychange'))
  })
}

/** Lets every call that is waiting on another settle, in the order the calls were made. */
async function settle(): Promise<void> {
  await act(async () => {
    for (let turn = 0; turn < 40; turn += 1) await Promise.resolve()
  })
}

async function shown(host: string): Promise<void> {
  await waitFor(() => {
    expect(rowsOf(host).length).toBeGreaterThan(0)
  })
}

function contactRows(): HTMLElement[] {
  return [...document.querySelectorAll<HTMLElement>('[data-testid="inbox-contact"]')]
}

function refusalRows(): HTMLElement[] {
  return [...document.querySelectorAll<HTMLElement>('[data-testid="inbox-refusal"]')]
}

const NOT_READ = 'The inbox could not be read'

describe('the contact rows come from the connection state', () => {
  // A choice and a forget start no loss, and a lease stop is a refusal: none is contact lost.
  it('a_choice_a_forget_and_a_lease_stop_start_no_loss_row', async () => {
    const { controls } = start()
    await shown('studio')
    const cases: readonly { readonly name: string; readonly contact: HostContact }[] = [
      { name: 'a choice', contact: { state: 'unknown' } },
      { name: 'a forget', contact: { state: 'unknown' } },
      {
        name: 'a lease stop',
        contact: { state: 'refused', refusal: REFUSAL, request: 'connection' }
      }
    ]
    for (const each of cases) {
      act(() => {
        controls.setConnected(false)
        controls.setContact(each.contact)
      })
      await settle()
      expect(contactRows().map((row) => row.getAttribute('data-host')), each.name).toEqual([])
    }
  })

  it('a_failed_read_of_the_state_claims_no_loss', async () => {
    start(null, (controls) => {
      controls.failConnectionReads('the connection cannot be read')
    })
    await settle()
    expect(contactRows()).toHaveLength(0)
    expect(document.body).not.toHaveTextContent(/out of contact/)
  })

  // The state names the host in use; a row of the others that names it as well is the same row.
  it('one_host_in_use_is_one_row', async () => {
    const { controls, port } = start()
    await shown('studio')
    const latest: ConnectionState = await port.connectionState()
    const lost: HostContact = { state: 'out_of_contact', since_ms: Date.now() - 1_000, escalates_at_ms: Date.now() + 59_000 }
    // The pairing screen already says the laptop is in use; the connection's state, which is held
    // back, still names the studio, and what the page shows is the state's.
    controls.holdPublications()
    act(() => {
      controls.setPairing({ hosts: [{ ...STUDIO, in_use: false }, { ...LAPTOP, in_use: true }] })
    })
    act(() => {
      controls.tellConnection({
        ...latest,
        revision: latest.revision + 1,
        connected: false,
        contact: lost,
        others: [{ reference: STUDIO.reference, name: 'studio', contact: lost, inbox_epoch: 1 }]
      })
    })
    await settle()
    expect(contactRows().map((row) => row.getAttribute('data-host'))).toEqual(['studio'])
  })

  it('a_lower_revision_never_replaces_a_higher_one', async () => {
    const { controls, port } = start()
    await shown('studio')
    const latest: ConnectionState = await port.connectionState()
    act(() => {
      controls.tellConnection({
        ...latest,
        revision: latest.revision - 1,
        connected: false,
        contact: { state: 'out_of_contact', since_ms: 1, escalates_at_ms: 2 }
      })
    })
    await settle()
    expect(contactRows()).toHaveLength(0)
    expect(rowsOf('studio').length).toBeGreaterThan(0)
  })

  it('a_refusal_then_a_recovery_both_apply', async () => {
    const { controls } = start(null)
    await shown('studio')
    act(() => {
      controls.setContact({ state: 'refused', refusal: REFUSAL, request: 'attention_read' })
      controls.setInboxEpoch(2)
    })
    await waitFor(() => {
      expect(refusalRows().map((row) => row.getAttribute('data-host'))).toEqual(['studio'])
    })
    act(() => {
      controls.setContact(null)
      controls.setInboxEpoch(3)
    })
    await waitFor(() => {
      expect(refusalRows()).toHaveLength(0)
    })
    await shown('studio')
  })
})

describe('what the host in use shows is stored and shown under the owner’s key', () => {
  it('a_refusal_hides_the_host_in_uses_items_counts_and_notes_in_every_filter', async () => {
    const { controls } = start(null)
    await shown('studio')
    act(() => {
      controls.setContact({ state: 'refused', refusal: REFUSAL, request: 'attention_read' })
      controls.setInboxEpoch(2)
    })
    await waitFor(() => {
      expect(refusalRows()).toHaveLength(1)
    })
    const filters = [...document.querySelectorAll<HTMLButtonElement>('.m-filters button')]
    expect(filters.length).toBeGreaterThan(1)
    for (const filter of filters) {
      act(() => {
        filter.click()
      })
      await settle()
      expect(rowsOf('studio'), filter.textContent ?? '').toHaveLength(0)
      expect(refusalRows(), filter.textContent ?? '').toHaveLength(1)
      expect(screen.queryByTestId('inbox-notes')).toBeNull()
      expect(filter.textContent ?? '').not.toMatch(/\(\d+\)/)
    }
  })

  // A read answers with the key it began under: one that ends after a refusal moved the epoch is
  // another epoch's and shows nothing.
  it('a_read_that_ends_after_the_refusal_restores_nothing', async () => {
    const { controls } = start(null)
    await shown('studio')
    const held = controls.hold('attentionRead')
    const first = held.count
    readNow()
    await settle()
    expect(held.count).toBe(first + 1)
    act(() => {
      controls.setContact({ state: 'refused', refusal: REFUSAL, request: 'attention_read' })
      controls.setInboxEpoch(2)
    })
    await settle()
    act(() => {
      held.answer(first)
    })
    await settle()
    expect(rowsOf('studio')).toHaveLength(0)
    expect(refusalRows()).toHaveLength(1)
  })

  it('a_read_that_began_before_a_refusal_and_ends_after_its_recovery_shows_nothing', async () => {
    const { controls } = start(null)
    await shown('studio')
    const held = controls.hold('attentionRead')
    const first = held.count
    readNow()
    await settle()
    act(() => {
      controls.setContact({ state: 'refused', refusal: REFUSAL, request: 'attention_read' })
      controls.setInboxEpoch(2)
    })
    await settle()
    act(() => {
      controls.setContact(null)
    })
    await settle()
    act(() => {
      held.answer(first)
    })
    await settle()
    expect(refusalRows()).toHaveLength(0)
    expect(rowsOf('studio')).toHaveLength(0)
  })

  // The host B is chosen and its publication is held: a read made then is answered under B's key, and
  // the page, which still holds A, files nothing of it under A. It reads again once B is applied.
  it('a_read_of_b_completed_while_b_is_unpublished_is_not_filed_under_a', async () => {
    const { controls } = start(null)
    await shown('studio')
    const release = controls.holdPublications()
    act(() => {
      controls.setPairing({ hosts: [{ ...STUDIO, in_use: false }, { ...LAPTOP, in_use: true }] })
    })
    readNow()
    await settle()
    expect(rowsOf('laptop')).toHaveLength(0)
    expect(rowsOf('studio').length).toBeGreaterThan(0)
    act(() => {
      release()
    })
    await shown('laptop')
    expect(rowsOf('studio')).toHaveLength(0)
  })

  it('a_page_of_the_read_with_another_key_discards_the_whole_read', async () => {
    const { controls } = start(null)
    await shown('studio')
    controls.pageInboxBy(1)
    const held = controls.hold('attentionRead')
    const first = held.count
    readNow()
    await settle()
    expect(held.count).toBe(first + 1)
    act(() => {
      held.answer(first)
      // The next page is asked after the first is answered, and the epoch moves before it is.
      controls.setInboxEpoch(2)
    })
    await settle()
    expect(held.count).toBeGreaterThan(first + 1)
    act(() => {
      held.answer(first + 1)
    })
    await settle()
    expect(screen.queryByText(NOT_READ)).toBeNull()
    expect(rowsOf('studio')).toHaveLength(0)
  })

  it('the_numbers_and_the_date_follow_the_same_key_but_a_failed_numbers_read_leaves_the_inbox', async () => {
    let numbers: HeldReads | null = null
    const { controls } = start(null, (scripted) => {
      numbers = scripted.hold('sessionNumbers')
    })
    await shown('studio')
    // The numbers of the first read are held; a reconnection moves the connection's number, so the
    // answer they make is under a key that is no longer the connection's.
    act(() => {
      controls.replaceConnection()
    })
    await settle()
    act(() => {
      numbers?.answer(0)
    })
    await settle()
    const row = rowsOf('studio')[0]
    expect(row).toHaveTextContent('A session')
    expect(row).not.toHaveTextContent(/Session \d/)
  })

  it('a_superseded_reply_makes_one_new_read_and_then_waits_for_the_cadence', async () => {
    const { controls } = start(null)
    await shown('studio')
    controls.supersedeNextInboxReads(2)
    const held = controls.hold('attentionRead')
    const first = held.count
    readNow()
    await settle()
    act(() => {
      held.answer(first)
    })
    await settle()
    // One read follows the one that was superseded; the second supersession starts none.
    expect(held.count).toBe(first + 2)
    act(() => {
      held.answer(first + 1)
    })
    await settle()
    expect(held.count).toBe(first + 2)
    expect(screen.queryByText(NOT_READ)).toBeNull()
    readNow()
    await settle()
    expect(held.count).toBe(first + 3)
  })

  it('a_reconnection_keeps_the_items_and_a_replacement_hides_them', async () => {
    const { controls } = start(null)
    await shown('studio')
    // Reads that begin from here on are held, so only what the page stored is on show.
    controls.hold('attentionRead')
    act(() => {
      controls.replaceConnection()
    })
    await settle()
    expect(rowsOf('studio').length).toBeGreaterThan(0)
    act(() => {
      controls.setInboxEpoch(2)
    })
    await settle()
    expect(rowsOf('studio')).toHaveLength(0)
  })

  // A refusal costs one read for each cadence and no more: it moves no trigger.
  it('a_persistent_refusal_costs_one_read_per_cadence_and_no_more', async () => {
    const { controls } = start(null)
    await shown('studio')
    const held: HeldReads = controls.hold('attentionRead')
    const first = held.count
    act(() => {
      controls.setContact({ state: 'refused', refusal: REFUSAL, request: 'attention_read' })
      controls.setInboxEpoch(2)
    })
    await settle()
    act(() => {
      controls.setInboxEpoch(3)
    })
    await settle()
    expect(held.count).toBe(first)
    readNow()
    await settle()
    expect(held.count).toBe(first + 1)
  })
})

describe('what another host shows is cached by epoch and serial', () => {
  it('a_refused_other_host_shows_no_cached_items', async () => {
    const { controls } = start()
    await shown('laptop')
    act(() => {
      // The visit before the refusal answers again after it: its row is of the epoch it was read under.
      controls.setOtherHosts([laptopOther(4, { state: 'refused', refusal: REFUSAL, request: 'attention_read' })])
    })
    await waitFor(() => {
      expect(refusalRows().map((row) => row.getAttribute('data-host'))).toEqual(['laptop'])
    })
    readNow()
    await settle()
    expect(rowsOf('laptop')).toHaveLength(0)
  })

  it('a_forgotten_host_leaves_no_cache_after_a_repair', async () => {
    const { controls } = start()
    await shown('laptop')
    const release = controls.holdInboxHosts()
    act(() => {
      controls.setPairing({ hosts: [STUDIO] })
    })
    await waitFor(() => {
      expect(rowsOf('laptop')).toHaveLength(0)
    })
    act(() => {
      controls.setPairing({ hosts: [STUDIO, LAPTOP] })
      controls.setOtherHosts([laptopOther(5)])
    })
    await settle()
    // The host is paired again and no pass has read it: nothing of the earlier pairing is shown.
    expect(rowsOf('laptop')).toHaveLength(0)
    release()
  })

  it('an_omitted_host_that_stays_paired_keeps_its_cache_while_its_epoch_holds', async () => {
    const { controls } = start()
    await shown('laptop')
    act(() => {
      controls.setInboxHosts([])
    })
    readNow()
    await settle()
    expect(rowsOf('laptop')).toHaveLength(1)
  })

  it('an_older_read_row_never_replaces_a_newer_cache', async () => {
    const { controls } = start({ row: laptopRow(3, 9, 'newer'), other: laptopOther(3) })
    await waitFor(() => {
      expect(rowsOf('laptop')[0]).toHaveTextContent('newer')
    })
    act(() => {
      controls.setInboxHosts([laptopRow(3, 7, 'older')])
    })
    readNow()
    await settle()
    expect(rowsOf('laptop')[0]).toHaveTextContent('newer')
    act(() => {
      controls.setInboxHosts([laptopRow(3, 10, 'newest')])
    })
    readNow()
    await waitFor(() => {
      expect(rowsOf('laptop')[0]).toHaveTextContent('newest')
    })
  })

  // The serial is the owner's, so a new pairing's first read is below an old cache's serial.
  it('a_new_pairings_first_read_replaces_an_old_cache_of_another_epoch', async () => {
    const { controls } = start({ row: laptopRow(3, 90, 'old pairing'), other: laptopOther(3) })
    await waitFor(() => {
      expect(rowsOf('laptop')[0]).toHaveTextContent('old pairing')
    })
    act(() => {
      controls.setOtherHosts([laptopOther(5)])
      controls.setInboxHosts([laptopRow(5, 2, 'new pairing')])
    })
    readNow()
    await waitFor(() => {
      expect(rowsOf('laptop')[0]).toHaveTextContent('new pairing')
    })
    expect(rowsOf('laptop')).toHaveLength(1)
  })
})

describe('the escalation of a loss', () => {
  // The other host is out of contact since 2,500 ms before the page opens, and the loss reaches its
  // next level 60,000 ms after it began: the mark appears at that instant, not before.
  it('the_urgent_mark_appears_at_the_escalation_instant', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'setInterval', 'clearInterval', 'Date'] })
    const opened = Date.now()
    const since = opened - 2_500
    const lost = laptopOther(3, { state: 'out_of_contact', since_ms: since, escalates_at_ms: since + 60_000 })
    const { controls } = start({ row: laptopRow(3, 7, 'laptop first'), other: lost })
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0)
    })
    expect(rowsOf('laptop').length).toBeGreaterThan(0)
    expect(contactRows()).toHaveLength(1)
    // Every read from here on is held, so only the clock moves the row.
    controls.hold('attentionRead')
    controls.hold('sessionNumbers')
    controls.holdInboxHosts()
    expect(contactRows()[0]).toHaveAttribute('data-level', 'notable')
    expect(within(contactRows()[0]).queryByText('Urgent')).toBeNull()
    await act(async () => {
      await vi.advanceTimersByTimeAsync(57_499)
    })
    expect(within(contactRows()[0]).queryByText('Urgent')).toBeNull()
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1)
    })
    expect(Date.now()).toBe(opened + 57_500)
    expect(contactRows()[0]).toHaveAttribute('data-level', 'urgent')
    expect(within(contactRows()[0]).getByText('Urgent')).toBeInTheDocument()
    expect(contactRows()[0]).toHaveTextContent(/laptop is out of contact/)
  })
})
