/**
 * KR-PERF-008: semantic updates batched at most once per animation frame, with input still
 * responsive during streamed output and a large history.
 *
 * Two measurements, both against the real components. The first counts renders while a host
 * publishes a burst of events: many events must produce one frame's work, not one render each. The
 * second types into the composer while that burst is arriving and measures what each keystroke
 * cost, because "responsive" is about the keystroke rather than about the average.
 *
 * Section 27 puts every measurement's figure and verdict where the run can be read afterwards, so
 * each one prints its numbers whether it met its bound or not.
 */

import { describe, expect, it } from 'vitest'
import { act, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import type { DocumentNode } from '@kalareach/plugin-sdk'

import { App } from '../src/App'
import { AppProvider } from '../src/app/state'
import { fakeHost } from '../src/host/fake'
import { FrameBatcher } from '../src/model/frame'

const SESSION_MAIN = '8a7b6c50-22bb-4c3d-8e4f-000000000101'

/**
 * How much more a keystroke may cost with a long history than with a short one.
 *
 * Not one, because a longer document does move more state around and this environment's timings
 * are noisy. Far below the growth a renderer that drew the whole history, or a composer that
 * re-rendered it on every key, would produce. The assertion that carries the real weight is the
 * one below it, which counts what the keystroke touched rather than how long it took.
 */
const MAXIMUM_GROWTH = 4

function node(index: number): DocumentNode {
  return {
    id: `stream-${index}`,
    revision: '1',
    body: { kind: 'message', author: 'agent', text: `token ${index}` }
  } as unknown as DocumentNode
}

/**
 * Appends a burst and waits for the whole of it to be on the screen.
 *
 * The batching under test is what makes this a wait at all: the events are folded into one frame's
 * work rather than rendered one at a time, so the screen catches up on an animation frame. What
 * follows waits for the last of the burst to be drawn, which is the batch having been published,
 * rather than for a length of time an animation frame is assumed to fit inside.
 */
async function burst(controls: { appendNode: (node: DocumentNode) => void }, count: number): Promise<void> {
  act(() => {
    for (let index = 0; index < count; index += 1) controls.appendNode(node(index))
  })
  await waitFor(() => {
    expect(
      screen.getByTestId('conversation-scroll').querySelector(`[data-node-id="stream-${count - 1}"]`)
    ).not.toBeNull()
  })
}

/** The middle sample, which is what a noisy environment's timings are read by. */
function median(samples: readonly number[]): number {
  const sorted = [...samples].sort((left, right) => left - right)
  const middle = Math.floor(sorted.length / 2)
  return sorted[middle] ?? 0
}

function record(name: string, figure: string, verdict: string): void {

  // a run that did not both have to leave one behind.
  console.log(`KR-PERF-008 ${name}: ${figure} (${verdict})`)
}

describe('KR-PERF-008', () => {
  it('folds a burst of events into one frame rather than one render each', () => {
    const published: number[] = []
    let scheduled: (() => void) | null = null
    const batcher = new FrameBatcher<DocumentNode>(
      (batch) => {
        published.push(batch.length)
      },
      (run) => {
        scheduled = run
      }
    )

    const events = 500
    for (let index = 0; index < events; index += 1) batcher.push(node(index))
    scheduled!()

    record(
      'batching',
      `${events} events in ${batcher.frames} frame${batcher.frames === 1 ? '' : 's'}`,
      batcher.frames === 1 ? 'met' : 'missed'
    )
    expect(batcher.frames).toBe(1)
    expect(published).toEqual([events])
  })

  it('keeps a keystroke the same cost however large the history is', async () => {
    const { port, controls } = fakeHost()
    render(
      <AppProvider
        port={port}
        initialPlace={{ view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' }}
      >
        <App />
      </AppProvider>
    )
    const input = await screen.findByTestId('composer-input')
    const user = userEvent.setup()

    // The figure that matters is not an absolute millisecond count, which is a property of the
    // machine and of this test environment's document. It is whether a keystroke costs more
    // because the session has a long history behind it. A renderer without a bounded window and a
    // composer that re-rendered the document would both show up here as growth.
    const measure = async (text: string, streaming: boolean): Promise<number[]> => {
      const samples: number[] = []
      for (const character of text) {
        if (streaming) controls.appendNode(node(100_000 + samples.length + text.length))
        const started = performance.now()
        await user.type(input, character)
        samples.push(performance.now() - started)
      }
      return samples
    }

    const small = median(await measure('short history', false))

    await burst(controls, 4_000)
    // One keystroke absorbs the frame that folds the whole backlog in. That frame is the batching
    // working, and it happens once; the steady state is what follows it.
    await user.type(input, '.')

    const large = median(await measure('long history', true))

    const growth = large / small
    record(
      'keystroke cost against history size',
      `${small.toFixed(2)} ms with a short history, ${large.toFixed(2)} ms with 4000 nodes and output streaming, growth ${growth.toFixed(2)}x`,
      growth <= MAXIMUM_GROWTH ? 'met' : 'missed'
    )

    expect(growth).toBeLessThanOrEqual(MAXIMUM_GROWTH)
  })

  it('touches nothing in the document when a key is pressed', async () => {
    const { port, controls } = fakeHost()
    render(
      <AppProvider
        port={port}
        initialPlace={{ view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' }}
      >
        <App />
      </AppProvider>
    )
    const input = await screen.findByTestId('composer-input')
    const document_ = await screen.findByTestId('conversation-scroll')

    await burst(controls, 2_000)

    // Counting what changed is the deterministic form of the measurement above: a composer that
    // re-rendered the document would show up here however fast the machine is.
    let mutations = 0
    const observer = new MutationObserver((records) => {
      mutations += records.length
    })
    observer.observe(document_, { childList: true, subtree: true, characterData: true })

    await userEvent.type(input, 'typing')
    await act(async () => {
      await Promise.resolve()
    })
    observer.disconnect()

    record('document mutations per keystroke', `${mutations} over 6 keystrokes`, mutations === 0 ? 'met' : 'missed')
    expect(mutations).toBe(0)
  })

  it('renders a bounded number of nodes however large the history is', async () => {
    const { port, controls } = fakeHost()
    render(
      <AppProvider
        port={port}
        initialPlace={{ view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' }}
      >
        <App />
      </AppProvider>
    )
    await screen.findByTestId('conversation')

    await burst(controls, 4_000)

    const rendered = screen.getByTestId('conversation-scroll').querySelectorAll('[data-node-id]')
    record('rendered nodes', `${rendered.length} of 4000 held`, rendered.length <= 200 ? 'met' : 'missed')
    // Bounded, and actually rendering: a window that drew nothing would pass an upper bound alone.
    expect(rendered.length).toBeGreaterThan(50)
    expect(rendered.length).toBeLessThanOrEqual(200)
  })
})
