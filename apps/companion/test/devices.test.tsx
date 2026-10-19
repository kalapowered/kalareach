/**
 * The devices of the hosts this computer owns, and revoking one, in the page.
 *
 * KR-REQ-10.46: the device list shows each host's last acknowledgement. The rule the screen holds
 * is that a revocation is never called done before the host's acknowledgement has been read: a
 * request that was sent says so, a request the host acknowledged while some of its sessions have yet
 * to confirm it says so, and only an acknowledgement that every session confirmed says the device is
 * revoked. The assertions are on what the screen offers, what the backend was asked, and the one fact
 * a person needs in each state, not on whole sentences. A host that is slow to answer is waited
 * for, and an answer is never replaced by one that began before it.
 */

import { act, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { AppProvider } from '../src/app/state'
import { fakeHost } from '../src/host/fake'
import type {
  RevocationDevice,
  RevocationFeed,
  RevocationHost,
  RevocationStanding,
  RevocationView
} from '../src/host/port'
import { Devices } from '../src/views/Devices'
import recorded from './fixtures/revocation-view.json'

const FEED: RevocationFeed = {
  read: true,
  problem: null,
  removed: false,
  host_wrote_here: true,
  last_acknowledgement: { at_ms: Date.UTC(2026, 9, 18, 9, 30), revision: 7, pending_workers: null },
  outstanding: 0,
  poll_interval_seconds: 30
}

function device(name: string, standing: RevocationStanding, over: Partial<RevocationDevice> = {}) {
  return {
    reference: name,
    name,
    platform: 'ios',
    manages_host: false,
    this_computer: false,
    standing,
    stale_since_ms: null,
    ...over
  } as const satisfies RevocationDevice
}

function host(over: Partial<RevocationHost> = {}): RevocationHost {
  return {
    reference: 'studio',
    name: 'the-studio',
    route: 'feed',
    contact: 'answered',
    listed_at_ms: Date.UTC(2026, 9, 18, 9, 31),
    host_synchronised_at_ms: null,
    host_feed_stale: false,
    devices: [device('the-phone', { state: 'active' })],
    feed: FEED,
    ...over
  }
}

function view(hosts: readonly RevocationHost[], over: Partial<RevocationView> = {}): RevocationView {
  return { ceremony: 'touch_id', feed_origin: 'reach.kala.to', hosts, ...over }
}

function screenOf(opened: RevocationView) {
  const { port, controls } = fakeHost()
  controls.revocation.change(opened)
  render(
    <AppProvider port={port}>
      <Devices />
    </AppProvider>
  )
  return { port, controls }
}

/** The row for `name`, once it is on the screen. Not for a case that fakes the timers. */
async function rowOf(name: string) {
  const row = (await screen.findAllByTestId('devices-device')).find((each) =>
    within(each).queryByText(name)
  )
  if (row === undefined) throw new Error(`no row for ${name}`)
  return row
}

const ACKNOWLEDGED = (over: { pending_workers?: number | null; host_lists_revoked?: boolean } = {}) =>
  ({
    state: 'acknowledged',
    at_ms: Date.UTC(2026, 9, 18, 9, 40),
    pending_workers: null,
    host_lists_revoked: true,
    ...over
  }) as const satisfies RevocationStanding

/** The row for `name`, at once. */
function rowNow(name: string) {
  const row = screen.getAllByTestId('devices-device').find((each) => within(each).queryByText(name))
  if (row === undefined) throw new Error(`no row for ${name}`)
  return row
}

/**
 * Lets what has already been answered reach the screen. A case that fakes the timers cannot wait
 * for a row the way the others do: the library's own waiting is a timer too.
 */
async function settle(): Promise<void> {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(0)
  })
}

describe('revoking a device', () => {
  afterEach(() => {
    vi.useRealTimers()
  })

  it('is called sent until the host has acknowledged it, and revoked only when it has', async () => {
    const person = userEvent.setup()
    const { controls } = screenOf(view([host()]))
    const before = await rowOf('the-phone')
    await person.click(within(before).getByRole('button', { name: /^Revoke with Touch ID: the-phone on the-studio/ }))

    expect(controls.revocation.asked).toEqual(['studio the-phone'])
    const sent = await rowOf('the-phone')
    await waitFor(() => {
      expect(within(sent).getByText('Sent')).toBeInTheDocument()
    })
    expect(within(sent).getByTestId('devices-standing')).toHaveTextContent('has not acknowledged')
    expect(within(sent).queryByText('Revoked')).not.toBeInTheDocument()
    // There is nothing left to press: the request waits for the host.
    expect(within(sent).queryByRole('button')).not.toBeInTheDocument()

    // The host's acknowledgement is read on the next look.
    controls.revocation.stand('studio', 'the-phone', ACKNOWLEDGED({ pending_workers: 2 }))
    await person.click(screen.getByTestId('devices-refresh'))
    await waitFor(() => {
      expect(within(sent).getByText('Acknowledged')).toBeInTheDocument()
    })
    expect(within(sent).getByTestId('devices-standing')).toHaveTextContent('2 sessions')
    expect(within(sent).queryByText('Revoked')).not.toBeInTheDocument()

    controls.revocation.stand('studio', 'the-phone', {
      state: 'done',
      at_ms: Date.UTC(2026, 9, 18, 9, 41)
    })
    await person.click(screen.getByTestId('devices-refresh'))
    await waitFor(() => {
      expect(within(sent).getByText('Revoked')).toBeInTheDocument()
    })
    // A person who cannot see the row hears it too.
    expect(screen.getByTestId('devices-heard')).toHaveTextContent('the-phone')
    expect(screen.getByTestId('devices-heard')).toHaveTextContent('every session confirmed it')
  })

  it('tells a person to revoke at the host when the host acknowledged and its own list does not bear it out', async () => {
    const person = userEvent.setup()
    const { controls } = screenOf(
      view([host({ devices: [device('the-phone', ACKNOWLEDGED())] })])
    )
    const row = await rowOf('the-phone')
    expect(within(row).queryByText(/Revoke it at the host/)).not.toBeInTheDocument()

    // The host's own list stops bearing the acknowledgement out: that changes what the person
    // should do, so it is heard as well as shown.
    controls.revocation.stand('studio', 'the-phone', ACKNOWLEDGED({ host_lists_revoked: false }))
    await person.click(screen.getByTestId('devices-refresh'))
    await waitFor(() => {
      expect(within(row).getByTestId('devices-standing')).toHaveTextContent(
        'Its own list does not show the device as revoked. Revoke it at the host.'
      )
    })
    expect(within(row).getByText('Acknowledged')).toBeInTheDocument()
    expect(within(row).queryByText('Revoked')).not.toBeInTheDocument()
    expect(screen.getByTestId('devices-heard')).toHaveTextContent('does not show it revoked')
  })

  it('is named for the ceremony this computer offers, and is not offered without one', async () => {
    const { port, controls } = fakeHost()
    controls.revocation.change(view([host()], { ceremony: 'windows_hello' }))
    const { unmount } = render(
      <AppProvider port={port}>
        <Devices />
      </AppProvider>
    )
    const row = await rowOf('the-phone')
    const control = within(row).getByRole('button', { name: /with Windows Hello/ })
    expect(control).toBeVisible()
    // The control's name begins with the words it shows, so speaking them finds it.
    expect(control.getAttribute('aria-label')?.startsWith(control.textContent ?? '')).toBe(true)
    unmount()

    controls.revocation.change(view([host()], { ceremony: 'none' }))
    render(
      <AppProvider port={port}>
        <Devices />
      </AppProvider>
    )
    const without = await rowOf('the-phone')
    expect(within(without).queryByRole('button')).not.toBeInTheDocument()
    expect(screen.getByText(/cannot check that it is you/)).toBeVisible()
  })

  it('says in the row that it went through nothing, and returns focus to the control, when the person did not confirm', async () => {
    const person = userEvent.setup()
    const { controls } = screenOf(view([host()]))
    controls.revocation.failWith('It was not confirmed, so nothing was changed.')
    const row = await rowOf('the-phone')
    const control = within(row).getByRole('button', { name: /^Revoke with Touch ID/ })
    await person.click(control)

    await waitFor(() => {
      expect(within(row).getByTestId('devices-failure')).toHaveTextContent('was not confirmed')
    })
    // The row still offers it, so the person can try again, and keyboard focus is back on it.
    await waitFor(() => {
      expect(control).toBeEnabled()
    })
    expect(control).toHaveFocus()
    expect(screen.getByTestId('devices-heard')).toHaveTextContent('Could not revoke the-phone')
  })

  it('does not claim that nothing changed when the request may have reached its host, and looks again', async () => {
    const person = userEvent.setup()
    const { port, controls } = screenOf(view([host()]))
    controls.revocation.failWith(
      'The host did not answer in time. This computer no longer shares its settings with that device, because the request may have reached the host.',
      'OUTCOME_UNKNOWN'
    )
    const row = await rowOf('the-phone')
    const asked = vi.spyOn(port, 'revocationView')
    await person.click(within(row).getByRole('button', { name: /^Revoke with Touch ID/ }))
    await waitFor(() => {
      expect(within(row).getByTestId('devices-failure')).toHaveTextContent('may have reached the host')
    })
    expect(within(row).getByTestId('devices-failure')).not.toHaveTextContent('Nothing was changed')
    // What the host and its feed say now is looked at, so the row shows a request that did leave.
    await waitFor(() => {
      expect(asked).toHaveBeenCalled()
    })
  })

  it('offers nothing for a host the feed removed or this computer could not read the feed of', async () => {
    const removed = host({
      reference: 'removed',
      name: 'the-attic',
      feed: { ...FEED, removed: true },
      devices: [device('the-tablet', { state: 'active' })]
    })
    const unread = host({
      reference: 'unread',
      name: 'the-shed',
      feed: { ...FEED, read: false, problem: 'it did not answer in time', last_acknowledgement: null },
      devices: [device('the-watch', { state: 'active' })]
    })
    screenOf(view([removed, unread]))

    expect(within(await rowOf('the-tablet')).queryByRole('button')).not.toBeInTheDocument()
    expect(within(await rowOf('the-watch')).queryByRole('button')).not.toBeInTheDocument()
    expect(screen.getByText(/removed the-attic/)).toBeVisible()
    expect(screen.getByText(/could not read the feed: it did not answer in time/)).toBeVisible()
    // A host the feed removed is not described as one that reads its feed.
    const attic = screen.getAllByTestId('devices-host').find((each) => within(each).queryByText('the-attic') !== null)
    expect(attic).toBeDefined()
    expect(attic).not.toHaveTextContent(/reads its feed/)
  })

  it('lists a host that does not answer from the list it gave last, with the time of that list', async () => {
    screenOf(view([host({ contact: 'silent' })]))
    const row = await rowOf('the-phone')
    expect(screen.getByText(/is not answering\. These are the devices it listed/)).toBeVisible()
    // A revocation is still sent through the feed.
    expect(within(row).getByRole('button', { name: /^Revoke with Touch ID/ })).toBeEnabled()
  })

  it('offers nothing for the host on this computer while it does not answer', async () => {
    screenOf(
      view([
        host({
          reference: 'here',
          name: 'This computer',
          route: 'direct',
          contact: 'silent',
          feed: null,
          devices: [device('the-phone', { state: 'active' })]
        })
      ])
    )
    const row = await rowOf('the-phone')
    expect(within(row).queryByRole('button')).not.toBeInTheDocument()
    // The host on this computer is called that, not "This computer", in a sentence.
    expect(screen.getByText(/The host on this computer is not answering/)).toBeVisible()
  })

  it('does not offer this computer to revoke itself', async () => {
    screenOf(
      view([
        host({
          devices: [
            device('this-mac', { state: 'active' }, { this_computer: true, manages_host: true })
          ]
        })
      ])
    )
    const row = await rowOf('this-mac')
    expect(within(row).queryByRole('button')).not.toBeInTheDocument()
  })

  it('offers a second request only for a refusal that a second request can get past', async () => {
    screenOf(
      view([
        host({
          devices: [
            device('the-first', { state: 'refused', reason: 'superseded' }),
            device('the-second', { state: 'refused', reason: 'unknown_target' }),
            device('the-third', { state: 'refused', reason: 'no_owner_authority' })
          ]
        })
      ])
    )
    expect(within(await rowOf('the-first')).getByRole('button', { name: /^Revoke again/ })).toBeEnabled()
    expect(within(await rowOf('the-second')).queryByRole('button')).not.toBeInTheDocument()
    const third = await rowOf('the-third')
    expect(within(third).queryByRole('button')).not.toBeInTheDocument()
    expect(within(third).getByTestId('devices-standing')).toHaveTextContent('Revoke the device at the host')
  })

  it('says where requests are published, and that a host must read that service', async () => {
    screenOf(view([host()]))
    await rowOf('the-phone')
    expect(screen.getByText(/Reached through its feed at reach\.kala\.to/)).toBeVisible()
  })

  it('shows a standing kept from an earlier read of the feed as that, with when it was read', async () => {
    screenOf(
      view([
        host({
          feed: { ...FEED, read: false, problem: 'it did not answer in time', last_acknowledgement: null },
          devices: [
            device(
              'the-phone',
              { state: 'sent', at_ms: Date.UTC(2026, 9, 18, 9, 40), host_lists_revoked: false },
              { stale_since_ms: Date.UTC(2026, 9, 18, 9, 42) }
            )
          ]
        })
      ])
    )
    const row = await rowOf('the-phone')
    expect(within(row).getByText('Sent')).toBeInTheDocument()
    expect(within(row).getByTestId('devices-standing')).toHaveTextContent('has not been able to read it since')
    // Nothing is offered: its feed cannot be read, and the request it holds is not sent again.
    expect(within(row).queryByRole('button')).not.toBeInTheDocument()
  })

  it('renders the view native code gives it, as recorded', async () => {
    // The fixture is serialised from native code's own types by a case in the native suite: a field
    // renamed on either side fails one of the two.
    const given = recorded as RevocationView
    screenOf(given)
    const rows = await screen.findAllByTestId('devices-device')
    expect(rows).toHaveLength(given.hosts.reduce((all, each) => all + each.devices.length, 0))
    const states = rows.map((each) => each.getAttribute('data-state'))
    for (const state of ['active', 'sent', 'acknowledged', 'done', 'refused', 'revoked']) {
      expect(states, state).toContain(state)
    }
    // Only the one standing native code calls done is called revoked, and a standing kept from an
    // earlier read says so.
    expect(screen.getAllByText('Revoked').length).toBe(1)
    expect(within(await rowOf('the-kindle')).getByTestId('devices-standing')).toHaveTextContent(
      'has not been able to read it since'
    )
    expect(screen.getByText(/the-attic is not answering/)).toBeVisible()
  })
})

describe('looking again while a request waits', () => {
  afterEach(() => {
    vi.useRealTimers()
  })

  /** A feed host with one device whose request was sent. */
  const waiting = () =>
    view([host({ devices: [device('the-phone', { state: 'sent', at_ms: Date.UTC(2026, 9, 18, 9, 40), host_lists_revoked: false })] })])

  it('waits for a slow host, shows its answer, and starts no second look beside it', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
    const { port, controls } = screenOf(waiting())
    await settle()
    const asked = vi.spyOn(port, 'revocationView')
    const row = rowNow('the-phone')
    expect(asked).toHaveBeenCalledTimes(0)
    // The host acknowledges; the next look is a slow one, and the person's place is in the words.
    controls.revocation.stand('studio', 'the-phone', ACKNOWLEDGED({ pending_workers: 1 }))
    const slow = controls.revocation.holdNextView()
    within(row).getByTestId('devices-standing').focus()
    await act(async () => {
      await vi.advanceTimersByTimeAsync(10_000)
    })
    expect(asked).toHaveBeenCalledTimes(1)
    // A look takes a minute; no other begins in that time, and Refresh waits with it.
    await act(async () => {
      await vi.advanceTimersByTimeAsync(60_000)
    })
    expect(asked).toHaveBeenCalledTimes(1)
    expect(screen.getByTestId('devices-refresh')).toBeDisabled()

    await act(async () => {
      slow.release()
      await vi.advanceTimersByTimeAsync(0)
    })
    expect(within(row).getByText('Acknowledged')).toBeInTheDocument()
    expect(screen.getByTestId('devices-refresh')).toBeEnabled()
    // The words that had focus are the same words, now saying more.
    expect(within(row).getByTestId('devices-standing')).toHaveFocus()
    // And it looks again ten seconds after that answer, not before.
    await act(async () => {
      await vi.advanceTimersByTimeAsync(9_000)
    })
    expect(asked).toHaveBeenCalledTimes(1)
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1_000)
    })
    expect(asked).toHaveBeenCalledTimes(2)
  })

  it('shows what a revocation answered, though a look that began before it answers after it', async () => {
    const person = userEvent.setup()
    const { controls } = screenOf(view([host()]))
    const row = await rowOf('the-phone')
    const slow = controls.revocation.holdNextView()
    // A look begins, and sees the device as nothing has been asked of it.
    await person.click(screen.getByTestId('devices-refresh'))
    await person.click(within(row).getByRole('button', { name: /^Revoke with Touch ID/ }))
    await waitFor(() => {
      expect(within(row).getByText('Sent')).toBeInTheDocument()
    })
    await act(async () => {
      slow.release()
      await Promise.resolve()
    })
    // The older look's answer does not take the request back out of the row.
    expect(within(row).getByText('Sent')).toBeInTheDocument()
    expect(within(row).queryByRole('button')).not.toBeInTheDocument()
    await waitFor(() => {
      expect(screen.getByTestId('devices-refresh')).toBeEnabled()
    })
  })

  it('asks again only about what a look can change', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
    const local = host({
      reference: 'here',
      name: 'This computer',
      route: 'direct',
      feed: null,
      devices: [device('the-phone', ACKNOWLEDGED({ pending_workers: 1 }))]
    })
    const { port } = screenOf(view([local]))
    await settle()
    const asked = vi.spyOn(port, 'revocationView')
    const row = rowNow('the-phone')
    expect(within(row).getByRole('button', { name: /^Check again/ })).toBeEnabled()
    // Only a revocation sent to the host on this computer changes what it says of one.
    await act(async () => {
      await vi.advanceTimersByTimeAsync(60_000)
    })
    expect(asked).not.toHaveBeenCalled()
  })

  it('does not look while the page is hidden, and looks when it is shown', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
    const { port } = screenOf(waiting())
    await settle()
    const asked = vi.spyOn(port, 'revocationView')
    rowNow('the-phone')
    const visibility = vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden')
    await act(async () => {
      await vi.advanceTimersByTimeAsync(30_000)
    })
    expect(asked).not.toHaveBeenCalled()
    visibility.mockReturnValue('visible')
    await act(async () => {
      document.dispatchEvent(new Event('visibilitychange'))
      await vi.advanceTimersByTimeAsync(0)
    })
    expect(asked).toHaveBeenCalledTimes(1)
    visibility.mockRestore()
  })
})
