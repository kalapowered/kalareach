/**
 * What the pairing screen says when the managed relay could not take an attempt: the ruled
 * sentences, this device's own wait said once in plain words, and the paths the service named,
 * shown as it wrote them.
 *
 * The scripted host stands in for native code. It publishes the failure native code sends, and what
 * is drawn is what the person reads.
 */

import { describe, expect, it, vi } from 'vitest'
import { act, render, screen, within } from '@testing-library/react'

import { App } from '../src/App'
import { AppProvider } from '../src/app/state'
import { fakeHost, type FakeHostControls } from '../src/host/fake'
import type { AttemptState, PairingFailure } from '../src/host/port'
import { failureAlternatives, waitInWords } from '../src/pairing/words'

function start(): { controls: FakeHostControls } {
  const { port, controls } = fakeHost()
  render(
    <AppProvider port={port} initialPlace={{ view: 'pairing' }}>
      <App />
    </AppProvider>
  )
  return { controls }
}

function attempt(controls: FakeHostControls, state: AttemptState): void {
  act(() => {
    controls.setPairing({ state })
  })
}

function failing(failure: PairingFailure, mode: 'code' | 'direct' = 'code'): AttemptState {
  return { state: 'ended', failure, mode, service: null }
}

/** The ruled sentence for a failure for want of capacity. */
function capacity(wait: string): string {
  return `The managed relay could not take this pairing now. Try again in about ${wait}, or bring this device onto the host's network.`
}

/** The ruled sentence for a fault of the managed relay service. */
function fault(wait: string): string {
  return `The managed relay service could not admit this pairing now. This is not a fault of the host. Try again in about ${wait}, or bring this device onto the host's network.`
}

const PATHS = [
  'A direct connection between the devices, which needs no managed relay.',
  "A relay that the host's owner runs and names in the host's configuration, used by a new invitation from that host."
]

/** What a person is told of the paths, or null when the screen shows no list. */
function listed(): { heading: string | null; paths: string[] } | null {
  const list = screen.queryByRole('list', { name: 'Until then:' })
  if (list === null) return null
  return {
    heading: screen.getByTestId('failure-alternatives').querySelector('p')?.textContent ?? null,
    paths: within(list)
      .getAllByRole('listitem')
      .map((item) => item.textContent ?? '')
  }
}

describe('a pairing that the managed relay could not take', () => {
  // KR-REQ-17.48: the wait is this device's own, said once as the host's own line says it.
  it.each([
    [0, '1 second'],
    [1, '1 second'],
    [2, '2 seconds'],
    [59, '59 seconds'],
    [60, '1 minute'],
    [61, '2 minutes'],
    [119, '2 minutes'],
    [120, '2 minutes'],
    [3_599, '1 hour'],
    [3_600, '1 hour'],
    [3_601, '2 hours'],
    [86_399, '24 hours'],
    [86_400, '24 hours'],
    [86_401, '24 hours'],
    [Number.MAX_SAFE_INTEGER, '24 hours'],
    [1e300, '24 hours']
  ])('says a wait of %s seconds as "%s"', (seconds, said) => {
    expect(waitInWords(seconds)).toBe(said)
  })

  // KR-REQ-17.48
  it('says capacity with the wait, then "Until then:" once and the paths as received', async () => {
    const { controls } = start()
    await screen.findByLabelText('Pairing code')
    attempt(
      controls,
      failing({ kind: 'relay_capacity', tries_left: null, retry_after_seconds: 90, alternatives: PATHS })
    )
    expect((await screen.findByTestId('failure-sentence')).textContent).toBe(capacity('2 minutes'))
    expect(listed()).toEqual({ heading: 'Until then:', paths: PATHS })
    expect(screen.getAllByText('Until then:')).toHaveLength(1)
    expect(screen.getByTestId('failure-action').textContent).toBe('Try again')
  })

  it('says capacity with no paths as the sentence alone: no "Until then:" and no list', async () => {
    const { controls } = start()
    await screen.findByLabelText('Pairing code')
    attempt(controls, failing({ kind: 'relay_capacity', tries_left: null, retry_after_seconds: 20 }))
    expect((await screen.findByTestId('failure-sentence')).textContent).toBe(capacity('20 seconds'))
    expect(screen.queryByText('Until then:')).toBeNull()
    expect(screen.queryByRole('list', { name: 'Until then:' })).toBeNull()
    expect(screen.queryByTestId('failure-alternatives')).toBeNull()

    // A list that arrives empty is no list.
    attempt(
      controls,
      failing({ kind: 'relay_capacity', tries_left: null, retry_after_seconds: 20, alternatives: [] })
    )
    expect(screen.queryByText('Until then:')).toBeNull()
    expect(screen.queryByTestId('failure-alternatives')).toBeNull()
  })

  it('says the fault with the wait, without a list and without a word about the host being at fault', async () => {
    const { controls } = start()
    await screen.findByLabelText('Pairing code')
    attempt(controls, failing({ kind: 'relay_fault', tries_left: null, retry_after_seconds: 600 }))
    expect((await screen.findByTestId('failure-sentence')).textContent).toBe(fault('10 minutes'))
    expect(screen.queryByText('Until then:')).toBeNull()
    expect(screen.queryByTestId('failure-alternatives')).toBeNull()
    expect(screen.getByTestId('failure-action').textContent).toBe('Try again')
  })

  // The client sends paths only with capacity. If a fault held them, the kind decides: the fault is
  // the service's own failure, and a path is a path the service named for want of capacity.
  it('shows no list for a fault that holds paths, nor for any kind but capacity', async () => {
    const { controls } = start()
    await screen.findByLabelText('Pairing code')
    attempt(
      controls,
      failing({ kind: 'relay_fault', tries_left: null, retry_after_seconds: 30, alternatives: PATHS })
    )
    expect((await screen.findByTestId('failure-sentence')).textContent).toBe(fault('30 seconds'))
    expect(listed()).toBeNull()
    expect(screen.queryByText('Until then:')).toBeNull()
    for (const text of PATHS) expect(screen.queryByText(text)).toBeNull()

    attempt(controls, failing({ kind: 'host_unreachable', tries_left: null, alternatives: PATHS }))
    expect(listed()).toBeNull()
    expect(screen.queryByText('Until then:')).toBeNull()
    expect(failureAlternatives({ kind: 'relay_fault', alternatives: PATHS })).toEqual([])
    expect(failureAlternatives({ kind: 'relay_capacity', alternatives: PATHS })).toEqual(PATHS)
  })

  it('says a failure of another kind as it always did', async () => {
    const { controls } = start()
    await screen.findByLabelText('Pairing code')
    attempt(controls, failing({ kind: 'host_unreachable', tries_left: 2 }))
    expect((await screen.findByTestId('failure-sentence')).textContent).toBe(
      "The host could not be reached. Check that this device is on the host's network, or that the host is online. 2 tries left on this device."
    )
    expect(screen.queryByTestId('failure-alternatives')).toBeNull()
  })

  it('says the tries that are left after the sentence, and the paths after that', async () => {
    const { controls } = start()
    await screen.findByLabelText('Pairing code')
    attempt(
      controls,
      failing({ kind: 'relay_capacity', tries_left: 3, retry_after_seconds: 45, alternatives: [PATHS[0] ?? ''] })
    )
    expect((await screen.findByTestId('failure-sentence')).textContent).toBe(
      `${capacity('45 seconds')} 3 tries left on this device.`
    )
    expect(listed()?.paths).toEqual([PATHS[0]])
  })

  it('says both kinds to a direct invitation, which is tried again only by bringing it in again', async () => {
    const { controls } = start()
    await screen.findByLabelText('Pairing code')
    for (const [kind, said] of [
      ['relay_capacity', capacity('1 second')],
      ['relay_fault', fault('1 second')]
    ] as const) {
      attempt(controls, failing({ kind, tries_left: null, retry_after_seconds: 0 }, 'direct'))
      expect((await screen.findByTestId('failure-sentence')).textContent).toBe(said)
      expect(screen.getByTestId('failure-action').textContent).toBe('Paste again')
    }
  })

  // KR-REQ-17.48: a path's text comes from the service. It is shown as characters, never as markup,
  // never as a link, and never changed: not trimmed, not joined, not dropped when repeated.
  it('shows a path as its characters, in the order received and unchanged', async () => {
    const { controls } = start()
    await screen.findByLabelText('Pairing code')
    const paths = [
      '<img src=x onerror="alert(1)"> <b>bold</b> & <a href="https://example.org/a">a link</a>',
      '  https://example.org/b  ',
      '<script>window.alerted = true</script>',
      '&amp; &lt;i&gt;',
      'same',
      'same'
    ]
    attempt(
      controls,
      failing({ kind: 'relay_capacity', tries_left: null, retry_after_seconds: 5, alternatives: paths })
    )
    await screen.findByTestId('failure-alternatives')
    const list = screen.getByRole('list', { name: 'Until then:' })
    expect(within(list).getAllByRole('listitem').map((item) => item.textContent)).toEqual(paths)
    expect(list.querySelector('img, b, a, i, script')).toBeNull()
    expect(within(list).queryAllByRole('link')).toEqual([])
  })

  // The wait is true at the moment the attempt ended: the page says it once and never counts it down.
  it('says the wait once and does not change it as time passes', async () => {
    vi.useFakeTimers()
    try {
      const { controls } = start()
      await act(async () => {
        for (let turn = 0; turn < 10; turn++) await Promise.resolve()
      })
      attempt(
        controls,
        failing({ kind: 'relay_capacity', tries_left: null, retry_after_seconds: 20, alternatives: PATHS })
      )
      const said = screen.getByTestId('failure-sentence').textContent
      expect(said).toBe(capacity('20 seconds'))
      act(() => {
        vi.advanceTimersByTime(10 * 60_000)
      })
      expect(screen.getByTestId('failure-sentence').textContent).toBe(said)
      expect((document.body.textContent ?? '').split('Try again in about')).toHaveLength(2)
      expect(listed()?.paths).toEqual(PATHS)
    } finally {
      vi.useRealTimers()
    }
  })
})
