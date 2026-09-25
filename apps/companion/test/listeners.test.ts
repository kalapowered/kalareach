/**
 * Listeners that say when they are listening.
 *
 * A view that reads a state and follows its changes has to know when its listener is registered,
 * because a change published before then reaches nobody. Every listener the port offers resolves
 * once it is registered, on the desktop shell and on the scripted host alike, and `watch` holds a
 * view's reads until all of its listeners are.
 */

import { afterEach, describe, expect, it, vi } from 'vitest'

import { fakeHost } from '../src/host/fake'
import { watch, type HostEvent } from '../src/host/port'
import { tauriPort } from '../src/host/tauri'
import type { AccountView } from '../src/model/account'

/** One registration the desktop shell has been asked for and has not completed yet. */
interface Asked {
  readonly event: string
  readonly handler: (published: { payload: unknown }) => void
  readonly complete: (unlisten: () => void) => void
}

const shell = vi.hoisted(() => ({ asked: [] as Asked[] }))

vi.mock('@tauri-apps/api/event', () => ({
  listen: (event: string, handler: (published: { payload: unknown }) => void) =>
    new Promise<() => void>((resolve) => {
      shell.asked.push({ event, handler, complete: resolve })
    })
}))

vi.mock('@tauri-apps/api/core', () => ({
  invoke: () => Promise.reject(new Error('no command is expected here'))
}))

afterEach(() => {
  shell.asked.length = 0
})

/** Whether `promise` has settled once everything already queued has run. */
async function settled(promise: Promise<unknown>): Promise<boolean> {
  let done = false
  void promise.then(
    () => {
      done = true
    },
    () => {
      done = true
    }
  )
  await new Promise((resolve) => {
    setTimeout(resolve, 0)
  })
  return done
}

/** A registration a test completes when it chooses. */
function pending(): {
  readonly registration: Promise<() => void>
  readonly complete: () => void
  readonly refuse: (reason: unknown) => void
  readonly stop: ReturnType<typeof vi.fn>
} {
  const stop = vi.fn()
  let complete = () => {}
  let refuse: (reason: unknown) => void = () => {}
  const registration = new Promise<() => void>((resolve, reject) => {
    complete = () => {
      resolve(stop)
    }
    refuse = reject
  })
  return { registration, complete, refuse, stop }
}

describe('the desktop shell', () => {
  it('resolves each listener only once the shell has registered it, with its stop', async () => {
    const port = tauriPort()
    const registrations = [
      port.onAccount(() => undefined),
      port.subscribe(() => undefined),
      port.onFilesDropped(() => undefined)
    ]
    expect(shell.asked.map((asked) => asked.event)).toEqual([
      'kr://account',
      'kr://event',
      'kr://dropped'
    ])
    for (const registration of registrations) {
      expect(await settled(registration)).toBe(false)
    }

    const unlistens = shell.asked.map((asked) => {
      const unlisten = vi.fn()
      asked.complete(unlisten)
      return unlisten
    })
    const stops = await Promise.all(registrations)
    stops.forEach((stop, index) => {
      expect(unlistens[index]).not.toHaveBeenCalled()
      stop()
      expect(unlistens[index]).toHaveBeenCalledTimes(1)
    })
  })

  it('hears the host events alone, with the stream and type each one names', async () => {
    const heard: HostEvent[] = []
    const registration = tauriPort().subscribe((event) => heard.push(event))
    // The connection's changes are `onConnection`'s, so this is the one registration made.
    expect(shell.asked.map((asked) => asked.event)).toEqual(['kr://event'])
    shell.asked[0].complete(() => undefined)
    await registration

    shell.asked[0].handler({
      payload: { stream_id: 'semantic:s-1', sequence: '4', event_type: 'node', payload: { id: 'n' } }
    })
    expect(heard).toEqual([
      { stream_id: 'semantic:s-1', sequence: '4', body: { kind: 'node', payload: { id: 'n' } } }
    ])
  })

  it('passes the account view and the dropped paths on as the page reads them', async () => {
    const views: AccountView[] = []
    const drops: unknown[] = []
    const port = tauriPort()
    const registrations = [
      port.onAccount((view) => views.push(view)),
      port.onFilesDropped((files) => drops.push(files))
    ]
    for (const asked of shell.asked) asked.complete(() => undefined)
    await Promise.all(registrations)

    shell.asked[0].handler({ payload: { state: 'browser_open' } })
    shell.asked[1].handler({ payload: ['/Users/sam/Desktop/diagram.png'] })
    expect(views).toEqual([{ state: 'browser_open' }])
    expect(drops).toEqual([
      [
        {
          name: 'diagram.png',
          media_type: 'application/octet-stream',
          byte_len: 0,
          path: '/Users/sam/Desktop/diagram.png'
        }
      ]
    ])
  })
})

describe('watching', () => {
  it('reads only once every listener is registered', async () => {
    const first = pending()
    const second = pending()
    const listening = vi.fn()
    watch([first.registration, second.registration], listening)

    first.complete()
    expect(await settled(first.registration)).toBe(true)
    expect(listening).not.toHaveBeenCalled()

    second.complete()
    await settled(second.registration)
    expect(listening).toHaveBeenCalledTimes(1)

    // With nothing to register, the read goes ahead, and a watch stopped first never reads.
    const nothing = vi.fn()
    watch([], nothing)
    const stopped = vi.fn()
    watch([], stopped).stop()
    await settled(Promise.resolve())
    expect(nothing).toHaveBeenCalledTimes(1)
    expect(stopped).not.toHaveBeenCalled()
  })

  it('stops every listener, even one registered after it stopped, and then reads nothing', async () => {
    const early = pending()
    const late = pending()
    const listening = vi.fn()
    const { stop } = watch([early.registration, late.registration], listening)

    early.complete()
    await settled(early.registration)
    stop()
    expect(early.stop).toHaveBeenCalledTimes(1)

    late.complete()
    await settled(late.registration)
    expect(late.stop).toHaveBeenCalledTimes(1)
    expect(listening).not.toHaveBeenCalled()
  })

  it('stops the others when one cannot be registered, and says why', async () => {
    const kept = pending()
    const refused = pending()
    const listening = vi.fn()
    const failed = vi.fn()
    watch([kept.registration, refused.registration], listening, failed)

    kept.complete()
    refused.refuse({ code: 'INTERNAL', message: 'The shell refused the listener.' })
    await settled(refused.registration)
    expect(kept.stop).toHaveBeenCalledTimes(1)
    expect(failed).toHaveBeenCalledWith({
      code: 'INTERNAL',
      message: 'The shell refused the listener.'
    })
    expect(listening).not.toHaveBeenCalled()
  })

  it('gives up at the first refusal, without waiting for a registration still on its way', async () => {
    const kept = pending()
    const refused = pending()
    const late = pending()
    const listening = vi.fn()
    const failed = vi.fn()
    watch([kept.registration, refused.registration, late.registration], listening, failed)

    kept.complete()
    refused.refuse({ code: 'INTERNAL', message: 'The shell refused the listener.' })
    await settled(refused.registration)
    expect(kept.stop).toHaveBeenCalledTimes(1)
    expect(failed).toHaveBeenCalledTimes(1)

    late.complete()
    await settled(late.registration)
    expect(late.stop).toHaveBeenCalledTimes(1)
    expect(failed).toHaveBeenCalledTimes(1)
    expect(listening).not.toHaveBeenCalled()
  })
})

describe('the reads a watch makes', () => {
  it('starts a read only once every listener is registered, and shows only the newest', async () => {
    const first = pending()
    const second = pending()
    const reads = watch([first.registration, second.registration])
    expect(reads.read()).toBeNull()

    first.complete()
    await settled(first.registration)
    expect(reads.read()).toBeNull()

    second.complete()
    await settled(second.registration)
    const older = reads.read()
    const newer = reads.read()
    expect(older?.()).toBe(false)
    expect(newer?.()).toBe(true)

    reads.stop()
    expect(newer?.()).toBe(false)
    expect(reads.read()).toBeNull()
  })

  it('ends its reads when a registration is refused', async () => {
    const kept = pending()
    const refused = pending()
    const reads = watch([kept.registration, refused.registration])

    kept.complete()
    refused.refuse({ code: 'INTERNAL', message: 'The shell refused the listener.' })
    await settled(refused.registration)
    expect(reads.read()).toBeNull()
  })
})

describe('the scripted host', () => {
  it('holds the account, host-event and dropped-file listeners with the others', async () => {
    const { port, controls } = fakeHost()
    const complete = controls.holdRegistrations()
    const views: AccountView[] = []
    const events: HostEvent[] = []
    const drops: unknown[] = []
    const registrations = [
      port.onAccount((view) => views.push(view)),
      port.subscribe((event) => events.push(event)),
      port.onFilesDropped((files) => drops.push(files))
    ]

    controls.account.set({ state: 'browser_open' })
    controls.emit({ stream_id: 'attention', sequence: '1', body: { kind: 'attention' } })
    controls.dropFiles([{ name: 'a.png', media_type: 'image/png', byte_len: 1, path: '/tmp/a.png' }])
    for (const registration of registrations) {
      expect(await settled(registration)).toBe(false)
    }
    expect([views, events, drops]).toEqual([[], [], []])

    complete()
    await Promise.all(registrations)
    controls.account.set({ state: 'finishing' })
    controls.emit({ stream_id: 'attention', sequence: '2', body: { kind: 'attention' } })
    controls.dropFiles([{ name: 'b.png', media_type: 'image/png', byte_len: 1, path: '/tmp/b.png' }])
    expect(views).toEqual([{ state: 'finishing' }])
    expect(events.map((event) => event.sequence)).toEqual(['2'])
    expect(drops).toHaveLength(1)
  })

  it('tells the connection listeners, and not the host-event stream, of a connection change', async () => {
    const { port, controls } = fakeHost()
    const events: HostEvent[] = []
    const states: boolean[] = []
    await Promise.all([
      port.subscribe((event) => events.push(event)),
      port.onConnection((state) => states.push(state.connected))
    ])

    controls.setConnected(false)
    expect(states).toEqual([false])
    expect(events).toEqual([])
  })

  it('answers each held read with what the host held when it was made, in any order', async () => {
    const { port, controls } = fakeHost()
    const held = controls.hold('connectionState')
    const before = port.connectionState()
    controls.setConnected(false)
    const after = port.connectionState()
    expect(held.count).toBe(2)
    expect(await settled(before)).toBe(false)

    held.answer(1)
    expect((await after).connected).toBe(false)
    expect(await settled(before)).toBe(false)
    held.answer(0)
    expect((await before).connected).toBe(true)

    // A read not made yet is not answered ahead of time: it waits like the others.
    held.answer(2)
    const later = port.connectionState()
    expect(held.count).toBe(3)
    expect(await settled(later)).toBe(false)
  })

  it('keeps a refusal as the held answer, and stops holding once released', async () => {
    const { port, controls } = fakeHost()
    const held = controls.hold('sessionRead')
    controls.setConnected(false)
    const refused = port.sessionRead({})
    controls.setConnected(true)
    expect(await settled(refused)).toBe(false)

    held.release()
    await expect(refused).rejects.toMatchObject({ code: 'RESOURCE_UNAVAILABLE' })
    // Released: the next read answers at once.
    expect(await settled(port.sessionRead({}))).toBe(true)
  })
})
