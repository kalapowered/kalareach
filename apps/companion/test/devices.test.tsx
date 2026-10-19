/**
 * The devices of the hosts this computer owns, and revoking one, in the page.
 *
 * KR-REQ-10.46: the device list shows each host's last acknowledgement. The rule the screen holds
 * is that a revocation is never called done before the host's acknowledgement has been read: a
 * request that was sent says so, a request the host acknowledged while some of its sessions run says
 * so, and only an acknowledgement that every session stopped says the device is revoked. The
 * assertions are on what the screen offers, what the backend was asked, and the one fact a person
 * needs in each state, not on whole sentences.
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

async function rowOf(name: string) {
  const row = (await screen.findAllByTestId('devices-device')).find((each) =>
    within(each).queryByText(name)
  )
  if (row === undefined) throw new Error(`no row for ${name}`)
  return row
}

describe('revoking a device', () => {
  afterEach(() => {
    vi.useRealTimers()
  })

  it('is called sent until the host has acknowledged it, and revoked only when it has', async () => {
    const person = userEvent.setup()
    const { controls } = screenOf(view([host()]))
    const before = await rowOf('the-phone')
    await person.click(within(before).getByRole('button', { name: /^Revoke the-phone on the-studio/ }))

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
    controls.revocation.stand('studio', 'the-phone', {
      state: 'acknowledged',
      at_ms: Date.UTC(2026, 9, 18, 9, 40),
      pending_workers: 2,
      host_lists_revoked: true
    })
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
    expect(screen.getByTestId('devices-heard')).toHaveTextContent('the-phone is revoked')
  })

  it('tells a person to revoke at the host when the host acknowledged and its own list does not bear it out', async () => {
    screenOf(
      view([
        host({
          devices: [
            device('the-phone', {
              state: 'acknowledged',
              at_ms: Date.UTC(2026, 9, 18, 9, 40),
              pending_workers: null,
              host_lists_revoked: false
            })
          ]
        })
      ])
    )
    const row = await rowOf('the-phone')
    expect(within(row).getByText('Acknowledged')).toBeInTheDocument()
    expect(within(row).getByTestId('devices-standing')).toHaveTextContent(
      'Its own list does not show the device as revoked. Revoke it at the host.'
    )
    expect(within(row).queryByText('Revoked')).not.toBeInTheDocument()
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
    expect(within(row).getByRole('button', { name: /with Windows Hello$/ })).toBeVisible()
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

  it('leaves the device as it was, and says so, when the person did not confirm', async () => {
    const person = userEvent.setup()
    const { controls } = screenOf(view([host()]))
    controls.revocation.refuseWith('It was not confirmed, so nothing was changed.')
    const row = await rowOf('the-phone')
    await person.click(within(row).getByRole('button', { name: /^Revoke the-phone/ }))

    await waitFor(() => {
      expect(screen.getByText('Nothing was changed')).toBeVisible()
    })
    expect(screen.getByText(/was not confirmed/)).toBeVisible()
    // The row still offers it, so the person can try again.
    expect(within(await rowOf('the-phone')).getByRole('button', { name: /^Revoke the-phone/ })).toBeEnabled()
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
  })

  it('lists a host that does not answer from the list it gave last, with the time of that list', async () => {
    screenOf(view([host({ contact: 'silent' })]))
    const row = await rowOf('the-phone')
    expect(screen.getByText(/is not answering\. These are the devices it listed at/)).toBeVisible()
    // A revocation is still sent through the feed.
    expect(within(row).getByRole('button', { name: /^Revoke the-phone/ })).toBeEnabled()
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

  it('says where requests are published, and that a host must read that service', async () => {
    screenOf(view([host()]))
    await rowOf('the-phone')
    expect(screen.getByText(/Reached through its feed at reach\.kala\.to/)).toBeVisible()
  })

  it('asks the local host again about a revocation it has not finished, and looks again while a request waits', async () => {
    vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] })
    const local = host({
      reference: 'here',
      name: 'This computer',
      route: 'direct',
      feed: null,
      devices: [
        device('the-phone', {
          state: 'acknowledged',
          at_ms: Date.UTC(2026, 9, 18, 9, 40),
          pending_workers: 1,
          host_lists_revoked: true
        })
      ]
    })
    const { port } = screenOf(view([local]))
    const asked = vi.spyOn(port, 'revocationView')
    const row = await rowOf('the-phone')
    expect(within(row).getByRole('button', { name: /^Check again/ })).toBeEnabled()

    await act(async () => {
      vi.advanceTimersByTime(10_000)
      await Promise.resolve()
    })
    expect(asked).toHaveBeenCalled()
  })
})
