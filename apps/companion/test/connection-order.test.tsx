/**
 * What the two shells show of a change of connection that native code tells out of order and twice,
 * and of one it never tells.
 *
 * A refusal and the recovery after it are each a revision of their own. The fake host makes them and
 * keeps them for a replay without telling the page, and then tells it the later one first, each of
 * them twice: the feed must hand every view each revision once and in order, and must find the last
 * change when no event brings it.
 */

import { act, render, waitFor } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import { App } from '../src/App'
import { AppProvider, type Place } from '../src/app/state'
import { fakeHost, type FakeHostControls } from '../src/host/fake'
import type { HostPort } from '../src/host/port'
import { receivedFailure } from '../src/host/tauri'
import { MobileApp } from '../src/mobile/MobileApp'

const UNREACHABLE = 'this host cannot be contacted right now'

/** A place that reads nothing about the connection itself, so every connection read is the shell's. */
const NEUTRAL: Place = { view: 'changesets' }

/** The port, and the revisions each view that follows the connection was shown, one list per view. */
function spied(port: HostPort): { port: HostPort; shown: number[][] } {
  const shown: number[][] = []
  return {
    shown,
    port: {
      ...port,
      watchConnection: (show, failed) => {
        const list: number[] = []
        shown.push(list)
        return port.watchConnection((state, resynced) => {
          list.push(state.revision)
          show(state, resynced)
        }, failed)
      }
    }
  }
}

/** A refusal and a recovery that were made and not told, and then told out of order and twice. */
function refusalThenRecovery(controls: FakeHostControls): void {
  controls.loseNextConnectionEvent()
  controls.setContact({
    state: 'refused',
    refusal: receivedFailure({
      code: 'PERMISSION_DENIED',
      message: 'The host would not take this device.',
      user_action: 'nothing',
      retry: 'no_retry'
    }),
    request: 'connection'
  })
  controls.loseNextConnectionEvent()
  controls.setContact(null)
  const [, refused, recovered] = controls.connectionHistory()
  if (refused === undefined || recovered === undefined) throw new Error('the changes were not made')
  act(() => {
    controls.tellConnection(recovered)
    controls.tellConnection(refused)
    controls.tellConnection(recovered)
    controls.tellConnection(refused)
  })
}

describe('a refusal and a recovery told out of order and twice', () => {
  it('are applied once each and in order on the desktop shell', async () => {
    const { port, controls } = fakeHost()
    const spy = spied(port)
    render(
      <AppProvider port={spy.port} initialPlace={NEUTRAL}>
        <App />
      </AppProvider>
    )
    await waitFor(() => {
      expect(spy.shown.length).toBeGreaterThan(0)
      expect(spy.shown.every((list) => list.length === 1)).toBe(true)
    })
    refusalThenRecovery(controls)
    await waitFor(() => {
      expect(port.connectionLatest()?.revision).toBe(3)
    })
    await waitFor(() => {
      expect(spy.shown.every((list) => list.length === 3)).toBe(true)
    })
    expect(spy.shown.every((list) => list.join() === '1,2,3')).toBe(true)
  })

  it('are applied once each and in order on the phone shell', async () => {
    const { port, controls } = fakeHost()
    const spy = spied(port)
    render(
      <AppProvider port={spy.port}>
        <MobileApp surface="ios" storage={null} />
      </AppProvider>
    )
    await waitFor(() => {
      expect(spy.shown.length).toBeGreaterThan(0)
      expect(spy.shown.every((list) => list.length === 1)).toBe(true)
    })
    refusalThenRecovery(controls)
    await waitFor(() => {
      expect(port.connectionLatest()?.revision).toBe(3)
    })
    await waitFor(() => {
      expect(spy.shown.every((list) => list.length === 3)).toBe(true)
    })
    expect(spy.shown.every((list) => list.join() === '1,2,3')).toBe(true)
  })
})

describe('a last change that no event brings', () => {
  it('is found on the desktop while the sessions view shows, with no view reading on a cadence', async () => {
    const { port, controls } = fakeHost()
    const { container } = render(
      <AppProvider port={port} initialPlace={{ view: 'sessions' }}>
        <App />
      </AppProvider>
    )
    const indicator = () => container.querySelector('.topbar .connection')?.textContent
    await waitFor(() => {
      expect(indicator()).toBe('Connected to this machine')
    })
    controls.loseNextConnectionEvent()
    act(() => {
      controls.setConnected(false)
    })
    // The event is lost, so the bar still says connected; the feed's own tail asks and finds it.
    expect(indicator()).toBe('Connected to this machine')
    await waitFor(
      () => {
        expect(indicator()).toBe(UNREACHABLE)
      },
      { timeout: 12_000 }
    )
  }, 20_000)
})
