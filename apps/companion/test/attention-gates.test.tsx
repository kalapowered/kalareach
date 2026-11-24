/**
 * What the desktop inbox shows, and when: the contact row comes from the connection's latest state,
 * and what the host in use said is stored and shown only under the owner's key (KR-REQ-13.01,
 * KR-REQ-13.02).
 *
 * The scripted host stands in for native code. A case holds the reads it needs to order and answers
 * them by index, or holds the connection's publications, so what decides each outcome is the order
 * of the calls and never the time a call takes. A case that counts reads, or that depends on a
 * clock, runs on one that only the test moves.
 */

import { act, cleanup, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { App } from '../src/App'
import { AppProvider } from '../src/app/state'
import { fakeHost, type FakeHostControls, type HeldReads } from '../src/host/fake'
import type { HostError, HostLabel } from '../src/host/port'
import { receivedFailure } from '../src/host/tauri'
import { ATTENTION_READ_CADENCE_MS } from '../src/model/attention'

afterEach(() => {
  cleanup()
  vi.useRealTimers()
})

const STUDIO: HostLabel = { kind: 'paired', reference: 'studio-reference', name: 'studio' }
const THIS_COMPUTER: HostLabel = { kind: 'local' }

const REFUSAL: HostError = receivedFailure({
  code: 'PERMISSION_DENIED',
  message: 'this device may not read this host',
  user_action: 'fix_configuration',
  retry: 'configuration_change'
})

const NOT_READ = 'This list could not be read'

/** The desktop application on the Attention screen, with the host as `before` leaves it. */
function start(before: (controls: FakeHostControls) => void = () => undefined): {
  readonly controls: FakeHostControls
} {
  const { port, controls } = fakeHost()
  before(controls)
  render(
    <AppProvider port={port} initialPlace={{ view: 'attention' }}>
      <App />
    </AppProvider>
  )
  return { controls }
}

/**
 * The same, on a clock that only the test moves: no cadence timer fires and no time passes until the
 * test advances it, so the reads a case counts are the ones its own calls make. The first read has
 * answered when it returns.
 */
async function startOnFakeClock(
  before: (controls: FakeHostControls) => void = () => undefined
): Promise<{ readonly controls: FakeHostControls }> {
  vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'setInterval', 'clearInterval', 'Date'] })
  const started = start(before)
  await act(async () => {
    await vi.advanceTimersByTimeAsync(0)
  })
  expect(screen.getByTestId('attention-list')).toBeInTheDocument()
  return started
}

/** Moves the test's clock on by `ms`, and lets what that set off settle. */
async function advance(ms: number): Promise<void> {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(ms)
  })
}

/** A loss that began `ago` ms ago and reaches its next level 60,000 ms after it began. */
function lostFor(ago: number): {
  readonly state: 'out_of_contact'
  readonly since_ms: number
  readonly escalates_at_ms: number
} {
  const since = Date.now() - ago
  return { state: 'out_of_contact', since_ms: since, escalates_at_ms: since + 60_000 }
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

function contactRows(): HTMLElement[] {
  return [...document.querySelectorAll<HTMLElement>('[data-testid="attention-contact"]')]
}

/** The rows the host raised, which are not the page's own row of contact. */
function itemRows(): HTMLElement[] {
  return [
    ...document.querySelectorAll<HTMLElement>(
      '[data-testid="attention-list"] [data-testid^="attention-"][data-kind]'
    )
  ].filter((each) => each.dataset.testid !== 'attention-contact')
}

/**
 * What the host's rows say about themselves: their labels, titles and the elapsed time they give. The
 * requests an approval row lists have clocks of their own, which are not this page's.
 */
function wordsOfItems(): string[] {
  return itemRows().map((each) =>
    [...each.querySelectorAll('.attention-top, h2, [data-testid="disconnected-note"]')]
      .map((part) => part.textContent)
      .join(' | ')
  )
}

function choose(label: string): void {
  const group = screen.getByRole('group', { name: 'Filter the inbox' })
  act(() => {
    within(group).getByRole('button', { name: label }).click()
  })
}

describe('the contact row comes from the connection state', () => {
  it('a_desktop_contact_row_shows_for_an_out_of_contact_host_in_use', async () => {
    const { controls } = start((host) => {
      host.setHostInUse(STUDIO)
      host.setContact(lostFor(2_500))
    })
    await waitFor(() => {
      expect(contactRows()).toHaveLength(1)
    })
    const row = contactRows()[0]
    expect(row).toHaveTextContent('studio is out of contact')
    expect(row).toHaveAttribute('data-level', 'notable')
    expect(row.textContent).toMatch(/may still be running; nothing here says they are not/)
    expect(row.textContent).not.toMatch(/failed|stuck|crashed/i)
    // The host on this computer is called by the shared title.
    act(() => {
      controls.setHostInUse(THIS_COMPUTER)
    })
    await waitFor(() => {
      expect(screen.getByTestId('attention-contact')).toHaveTextContent('This computer is out of contact')
    })
    // It is told under "Everything" and "Out of contact", and under no other filter.
    for (const label of ['Decisions', 'Failures', 'To review', 'Notices']) {
      choose(label)
      expect(contactRows(), label).toHaveLength(0)
    }
    for (const label of ['Out of contact', 'Everything']) {
      choose(label)
      expect(contactRows(), label).toHaveLength(1)
    }
  })

  it('a_desktop_empty_state_counts_the_contact_row', async () => {
    start((host) => {
      host.setHostInUse(STUDIO)
      host.setContact(lostFor(2_500))
    })
    choose('Out of contact')
    const raised = await screen.findByTestId('attention-disconnected')
    act(() => {
      within(raised).getByTestId('acknowledge').click()
    })
    await waitFor(() => {
      expect(screen.queryByTestId('attention-disconnected')).toBeNull()
    })
    expect(screen.queryByText('No item here says that a host is out of contact.')).toBeNull()
    expect(contactRows()).toHaveLength(1)
  })

  it('a_desktop_could_not_be_read_gives_way_to_the_row', async () => {
    const { controls } = start((host) => {
      host.setHostInUse(STUDIO)
    })
    await screen.findByTestId('attention-list')
    // The host stops answering: the state says it is out of contact, and every read fails.
    act(() => {
      controls.setConnected(false, 'The host does not answer.')
    })
    readNow()
    await settle()
    expect(screen.queryByText(NOT_READ)).toBeNull()
    expect(contactRows()).toHaveLength(1)
    expect(contactRows()[0]).toHaveTextContent('studio is out of contact')
  })

  // The host on this computer that was never reached has no loss to tell. It is first given one, so
  // the case holds only where a row can show.
  it('a_desktop_never_reached_local_host_shows_no_row', async () => {
    const { controls } = start((host) => {
      host.setHostInUse(THIS_COMPUTER)
      host.setContact(lostFor(2_500))
    })
    await waitFor(() => {
      expect(contactRows()).toHaveLength(1)
    })
    act(() => {
      controls.setContact({ state: 'unknown' })
    })
    await waitFor(() => {
      expect(contactRows()).toHaveLength(0)
    })
    expect(screen.queryByText(NOT_READ)).toBeNull()
  })

  it('a_desktop_refused_host_in_use_shows_no_loss_row', async () => {
    const { controls } = start((host) => {
      host.setHostInUse(STUDIO)
    })
    await screen.findByTestId('attention-list')
    act(() => {
      controls.setContact({ state: 'refused', refusal: REFUSAL, request: 'attention_read' })
      controls.setInboxEpoch(2)
    })
    readNow()
    await settle()
    expect(contactRows()).toHaveLength(0)
    expect(screen.queryByText(/is out of contact/)).toBeNull()
  })
})

describe('what the host in use shows is stored and shown under the owner’s key', () => {
  it('a_desktop_refused_host_in_use_hides_its_cached_items', async () => {
    const { controls } = start((host) => {
      host.setHostInUse(STUDIO)
    })
    await screen.findByTestId('attention-list')
    expect(itemRows().length).toBeGreaterThan(0)
    // The host refuses, which moves its epoch, and the read that follows fails.
    act(() => {
      controls.setContact({ state: 'refused', refusal: REFUSAL, request: 'attention_read' })
      controls.setInboxEpoch(2)
      controls.setConnected(false, 'This device was refused.')
    })
    readNow()
    await settle()
    expect(screen.getByText(NOT_READ)).toBeInTheDocument()
    expect(itemRows()).toHaveLength(0)
    expect(screen.queryByTestId('attention-list')).toBeNull()
    expect(screen.queryByTestId('inbox-notes')).toBeNull()
  })

  // A read answers with the key it began under, and the page keeps it only while that is the key of
  // the connection's latest state at the moment it ends. Either the state the read was made under is
  // gone when it ends (the completion is late), or the host moved before the page was told (the
  // publication is late): in both, the read is dropped and one new read follows.
  it('a_desktop_result_with_another_key_is_dropped_whether_its_publication_or_its_completion_is_held', async () => {
    const { controls } = await startOnFakeClock((host) => {
      host.setHostInUse(STUDIO)
    })
    const held = controls.hold('attentionRead')
    const first = held.count

    // The completion is held: the read began at epoch 1, and the state moves to epoch 2 before it ends.
    readNow()
    await settle()
    expect(held.count).toBe(first + 1)
    act(() => {
      controls.setInboxEpoch(2)
    })
    await settle()
    act(() => {
      held.answer(first)
    })
    await settle()
    expect(held.count).toBe(first + 2)
    act(() => {
      held.answer(first + 1)
    })
    await settle()
    expect(screen.getByTestId('attention-list')).toBeInTheDocument()

    // The publication is held: the host is at epoch 3, and the page still holds epoch 2.
    const release = controls.holdPublications()
    act(() => {
      controls.setInboxEpoch(3)
    })
    readNow()
    await settle()
    const second = held.count - 1
    act(() => {
      held.answer(second)
    })
    await settle()
    // The read of epoch 3 is not filed under epoch 2: the rows of epoch 2 are still the ones shown,
    // and one new read follows.
    expect(screen.getByTestId('attention-list')).toBeInTheDocument()
    expect(held.count).toBe(second + 2)
    act(() => {
      held.answer(second + 1)
    })
    await settle()
    expect(screen.getByTestId('attention-list')).toBeInTheDocument()
    act(() => {
      release()
    })
    await settle()
    // The page is told epoch 3. What it holds is epoch 2's, so it shows nothing until a read of
    // epoch 3 ends.
    expect(screen.queryByTestId('attention-list')).toBeNull()
    readNow()
    await settle()
    act(() => {
      held.answer(held.count - 1)
    })
    await settle()
    expect(screen.getByTestId('attention-list')).toBeInTheDocument()
  })

  // A change of host that comes while a read is on its way asks for a read of its own. The one new
  // read that follows a dropped answer is that read, so two drops across the change make two reads.
  it('a_desktop_change_of_host_during_a_dropped_read_is_read_by_the_retry_and_not_again', async () => {
    const { controls } = await startOnFakeClock((host) => {
      host.setHostInUse(STUDIO)
    })
    controls.supersedeNextInboxReads(2)
    const held = controls.hold('attentionRead')
    const first = held.count
    readNow()
    await settle()
    expect(held.count).toBe(first + 1)
    act(() => {
      controls.setHostInUse(THIS_COMPUTER)
    })
    await settle()
    // The change asks for no read while one is on its way.
    expect(held.count).toBe(first + 1)
    act(() => {
      held.answer(first)
    })
    await settle()
    expect(held.count).toBe(first + 2)
    act(() => {
      held.answer(first + 1)
    })
    await settle()
    expect(held.count).toBe(first + 2)
  })

  // The retry covers the change that came before it began and no later one.
  it('a_desktop_change_of_host_during_the_retry_still_makes_a_read_of_its_own', async () => {
    const { controls } = await startOnFakeClock((host) => {
      host.setHostInUse(STUDIO)
    })
    controls.supersedeNextInboxReads(1)
    const held = controls.hold('attentionRead')
    const first = held.count
    readNow()
    await settle()
    act(() => {
      held.answer(first)
    })
    await settle()
    expect(held.count).toBe(first + 2)
    act(() => {
      controls.setHostInUse(THIS_COMPUTER)
    })
    await settle()
    expect(held.count).toBe(first + 2)
    act(() => {
      held.answer(first + 1)
    })
    await settle()
    expect(held.count).toBe(first + 3)
  })

  // A numbers read that fails leaves the inbox and clears the numbers the rows were drawn with, so
  // they say "A session" and never the number of an earlier read.
  it('a_desktop_failed_numbers_read_after_a_successful_one_clears_the_numbers', async () => {
    const { controls } = start((host) => {
      host.setHostInUse(STUDIO)
    })
    await waitFor(() => {
      expect(itemRows()[0]).toHaveTextContent(/Session \d/)
    })
    controls.failNextSessionList('the host could not list its sessions')
    readNow()
    await waitFor(() => {
      expect(itemRows()[0]).toHaveTextContent('A session')
    })
    expect(itemRows()[0]).not.toHaveTextContent(/Session \d/)
    expect(screen.queryByText(NOT_READ)).toBeNull()
  })

  // A numbers read that is dropped, under another key than the connection's, is a drop like the
  // inbox's: one new read follows and a second drop waits for the cadence.
  it('a_desktop_numbers_only_drop_makes_one_new_read_and_then_waits_for_the_cadence', async () => {
    const { controls } = await startOnFakeClock((host) => {
      host.setHostInUse(STUDIO)
    })
    const numbers = controls.hold('sessionNumbers')
    const first = numbers.count
    readNow()
    await settle()
    expect(numbers.count).toBe(first + 1)
    // The epoch moves with no trigger, so the answer the read makes is under a key that is gone.
    act(() => {
      controls.setInboxEpoch(2)
    })
    await settle()
    act(() => {
      numbers.answer(first)
    })
    await settle()
    expect(numbers.count).toBe(first + 2)
    act(() => {
      controls.setInboxEpoch(3)
    })
    await settle()
    act(() => {
      numbers.answer(first + 1)
    })
    await settle()
    expect(numbers.count).toBe(first + 2)
    readNow()
    await settle()
    expect(numbers.count).toBe(first + 3)
  })

  it('a_desktop_superseded_reply_makes_one_new_read', async () => {
    const { controls } = await startOnFakeClock((host) => {
      host.setHostInUse(STUDIO)
    })
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
    // The cadence reads again once it has passed since the answer, and not before.
    await advance(ATTENTION_READ_CADENCE_MS - 1)
    expect(held.count).toBe(first + 2)
    await advance(1)
    expect(held.count).toBe(first + 3)
  })

  // The numbers are kept under a key of their own: the answer of a read that began on the connection
  // before a replacement is not the new connection's, and a replacement hides the numbers it moved.
  it('a_desktop_numbers_follow_the_same_key_as_the_inbox', async () => {
    let numbers: HeldReads | null = null
    const { controls } = start((host) => {
      host.setHostInUse(STUDIO)
      numbers = host.hold('sessionNumbers')
    })
    await screen.findByTestId('attention-list')
    act(() => {
      controls.replaceConnection()
    })
    await settle()
    act(() => {
      numbers?.answer(0)
    })
    await settle()
    expect(itemRows()[0]).toHaveTextContent('A session')
    expect(itemRows()[0]).not.toHaveTextContent(/Session \d/)
  })

  it('a_desktop_replacement_leaves_the_old_numbers_unshown_while_the_new_numbers_are_unread', async () => {
    const { controls } = start((host) => {
      host.setHostInUse(STUDIO)
    })
    await waitFor(() => {
      expect(itemRows()[0]).toHaveTextContent(/Session \d/)
    })
    controls.hold('sessionNumbers')
    act(() => {
      controls.setInboxEpoch(2)
      controls.replaceConnection()
    })
    await waitFor(() => {
      expect(itemRows()[0]).toHaveTextContent('A session')
    })
    expect(itemRows()[0]).not.toHaveTextContent(/Session \d/)
  })

  it('a_connection_change_starts_a_read', async () => {
    const { controls } = await startOnFakeClock()
    const held = controls.hold('attentionRead')
    const first = held.count
    act(() => {
      controls.setHostInUse(STUDIO)
    })
    await settle()
    expect(held.count).toBe(first + 1)
  })

  // A refusal moves the epoch and no more: the page reads a refused host on its cadence and not once
  // for each change the host makes to its record.
  it('a_desktop_persistent_refusal_costs_one_read_per_cadence_and_no_more', async () => {
    const { controls } = await startOnFakeClock((host) => {
      host.setHostInUse(STUDIO)
    })
    const held = controls.hold('attentionRead')
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
    await advance(ATTENTION_READ_CADENCE_MS - 1)
    expect(held.count).toBe(first)
    await advance(1)
    expect(held.count).toBe(first + 1)
  })
})

describe('the escalation of a loss', () => {
  // The host in use is out of contact since 2,500 ms before the page opens, and the loss reaches its
  // next level 60,000 ms after it began: the mark appears at that instant, not before, and with no
  // read answering it moves that row and no other.
  it('a_desktop_urgent_mark_at_60000_ms_drives_only_that_row', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'setInterval', 'clearInterval', 'Date'] })
    const opened = Date.now()
    const { controls } = start((host) => {
      host.setHostInUse(STUDIO)
      host.setContact(lostFor(2_500))
    })
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0)
    })
    expect(itemRows().length).toBeGreaterThan(0)
    // Every read from here on is held, so only the clock moves anything.
    controls.hold('attentionRead')
    controls.hold('sessionNumbers')
    const before = wordsOfItems()
    expect(contactRows()).toHaveLength(1)
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
    expect(wordsOfItems()).toEqual(before)
  })

  // The host in use is told out of contact after the instant its loss reaches its next level, while
  // every read is held: the clock has no timer to wait for, so the state itself moves it.
  it('a_desktop_loss_told_after_its_instant_is_urgent_at_once', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'setInterval', 'clearInterval', 'Date'] })
    const { controls } = start((host) => {
      host.setHostInUse(STUDIO)
    })
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0)
    })
    expect(itemRows().length).toBeGreaterThan(0)
    // Every read from here on is held, so only the state and the clock move the page.
    controls.hold('attentionRead')
    controls.hold('sessionNumbers')
    await act(async () => {
      await vi.advanceTimersByTimeAsync(10_000)
    })
    const since = Date.now() - 61_000
    act(() => {
      controls.setContact({ state: 'out_of_contact', since_ms: since, escalates_at_ms: since + 60_000 })
    })
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0)
    })
    expect(contactRows()).toHaveLength(1)
    expect(contactRows()[0]).toHaveAttribute('data-level', 'urgent')
    expect(within(contactRows()[0]).getByText('Urgent')).toBeInTheDocument()
  })
})
