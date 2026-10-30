/**
 * KR-PERF-008, the responsiveness half: the interface keeps input responsive while tool output
 * streams in and the history behind it is large.
 *
 * The component test next to the interface counts what a keystroke touches and how its cost grows
 * with the history, in a document that has no renderer. What it cannot show is when a key reaches
 * the screen. Here the keys are typed through the browser's input pipeline, and each is timed from
 * the event's own time stamp to the start of the second animation frame after it: the frame that
 * follows the one that presented the key's effect. A page that is busy with the stream presents
 * that frame late, so the figure includes input delay, the handler's work and the wait for a
 * paint. It is an indirect measure of the paint: the figure never reads the composer's pixels. The
 * composer is a native `textarea`, whose text the browser paints in the frame that follows the
 * key's event, so the second frame after the event stands for it.
 *
 * The figure is a recording. Section 27 gives this target no number, and a bound on elapsed time
 * would judge the machine the run happens on as much as the interface, so the case asserts only
 * conditions: every key reached the composer in order and was timed, and the stream advanced on
 * the screen while the keys were typed. The only time limits are Playwright's: 90 seconds for the
 * case, which is raised from the default of 30 because a slower engine on a hosted runner draws
 * 4,000 nodes slowly, and the default 5 seconds for each `expect`. The readings are the
 * median of the keys in frame periods of the page's own idle frames and against the same keys with
 * a short history and nothing streaming; each is printed with the engine, the host it was taken on
 * and a verdict against the reference bounds below, and attached to the run. The verdict is for a
 * person who runs this spec on a reference host to read, and no run of `scripts/bench-all.sh`
 * takes it: a display's frame period does not change with the processor, so the same bounds are
 * tighter on a slower machine.
 */

import { arch, cpus, platform, release, totalmem } from 'node:os'

import { expect, test, type Page } from '@playwright/test'

/** How many nodes the history holds before the stream starts. */
const HISTORY = 4_000

/** How many nodes the stream adds in each animation frame while the keys are typed. */
const PER_FRAME = 20

/** The keys typed for each reading, one every `PAUSE_MS` so that each is its own interaction. */
const KEYS = 'responsive input'.repeat(3)
const PAUSE_MS = 40

/**
 * The reference bounds the verdict line reads the readings against: the most frame periods the
 * middle key may wait with the stream running over the full history, and how much later it may be
 * than with a short history and nothing streaming. Section 27 gives this target no number, so these
 * two are this case's own reading of "responsive", chosen to be read and not to be held to. They
 * are not asserted.
 */
const REFERENCE_PERIODS = 4
const REFERENCE_GROWTH = 3

declare global {
  interface Window {
    /** What the page has measured of its keys, and the stream it is running. */
    krKeys?: { samples: number[]; names: string[]; pending: number; stop: () => void; drawn: () => number }
  }
}

async function openSession(page: Page): Promise<void> {
  await page.goto('/harness.html')
  await page.waitForSelector('.app-shell')
  await page.getByRole('button', { name: 'Sessions' }).click()
  await page.getByTestId('session-row-1').click()
  await page.getByTestId('conversation').waitFor()
  await page.getByTestId('composer-input').waitFor()
}

/** The middle of the samples, which is how a noisy machine's timings are read. */
function median(samples: readonly number[]): number {
  const sorted = [...samples].sort((left, right) => left - right)
  return sorted[Math.floor(sorted.length / 2)] ?? 0
}

function percentile(samples: readonly number[], fraction: number): number {
  const sorted = [...samples].sort((left, right) => left - right)
  return sorted[Math.min(sorted.length - 1, Math.ceil(sorted.length * fraction) - 1)] ?? 0
}

/** The machine the browser runs on, which a reading depends on and is recorded beside. */
function host(): { os: string; arch: string; processor: string; logicalProcessors: number; memoryMiB: number } {
  const processors = cpus()
  return {
    os: `${platform()} ${release()}`,
    arch: arch(),
    processor: processors[0]?.model ?? 'not reported here',
    logicalProcessors: processors.length,
    memoryMiB: Math.round(totalmem() / (1024 * 1024))
  }
}

/** The page's frame period when it is idle: the middle of the gaps between 40 frames. */
async function framePeriod(page: Page): Promise<number> {
  return page.evaluate(
    () =>
      new Promise<number>((resolve) => {
        const gaps: number[] = []
        let last = performance.now()
        const tick = (now: number): void => {
          gaps.push(now - last)
          last = now
          if (gaps.length < 40) requestAnimationFrame(tick)
          else resolve([...gaps].sort((a, b) => a - b)[Math.floor(gaps.length / 2)] ?? 0)
        }
        requestAnimationFrame(tick)
      })
  )
}

/**
 * Starts timing keys in the page: each key is timed from its event's time stamp to the start of
 * the second animation frame after it.
 */
async function startTiming(page: Page): Promise<void> {
  await page.evaluate(() => {
    const keys = { samples: [] as number[], names: [] as string[], pending: 0, stop: () => undefined, drawn: () => 0 }
    window.krKeys = keys
    document.addEventListener(
      'keydown',
      (event) => {
        const began = event.timeStamp
        keys.names.push(event.key)
        keys.pending += 1
        requestAnimationFrame(() =>
          requestAnimationFrame(() => {
            keys.samples.push(performance.now() - began)
            keys.pending -= 1
          })
        )
      },
      true
    )
  })
}

/**
 * Types the keys and returns the time of each, once the last has been timed, with how far the
 * stream had been drawn when the first key went in, after the composer was emptied, and when the
 * last key's timing was read, in the same call as the times.
 */
async function typeKeys(page: Page): Promise<{ times: number[]; drawnBefore: number; drawnAfter: number }> {
  const composer = page.getByTestId('composer-input')
  // Emptying the composer presses a key of its own, so it is done, and timed, before the timing
  // is cleared.
  await composer.fill('')
  await composer.focus()
  await page.waitForFunction(() => window.krKeys?.pending === 0)
  await page.evaluate(() => {
    if (window.krKeys) {
      window.krKeys.samples.length = 0
      window.krKeys.names.length = 0
    }
  })
  const drawnBefore = await page.evaluate(() => window.krKeys?.drawn() ?? -1)
  await page.keyboard.type(KEYS, { delay: PAUSE_MS })
  await page.waitForFunction(() => window.krKeys?.pending === 0 && (window.krKeys?.samples.length ?? 0) > 0)
  const read = await page.evaluate(() => ({
    times: [...(window.krKeys?.samples ?? [])],
    drawnAfter: window.krKeys?.drawn() ?? -1
  }))
  return { times: read.times, drawnBefore, drawnAfter: read.drawnAfter }
}

test.describe('KR-PERF-008: input stays responsive while output streams over a large history', () => {
  test('a key is timed to the second frame after it while 20 nodes a frame stream over 4000', async ({ page }) => {
    test.setTimeout(90_000)
    const engine = test.info().project.name
    await openSession(page)
    await startTiming(page)
    const period = await framePeriod(page)

    // Short history, nothing streaming: what a key costs on this machine in this engine.
    const { times: quiet } = await typeKeys(page)
    expect(await page.getByTestId('composer-input').inputValue()).toBe(KEYS)

    // The history, appended in one go, and drawn: its last node is in the conversation's window.
    await page.evaluate((count) => {
      const host = window.krTestHost
      if (!host) throw new Error('the harness has no scripted host')
      for (let index = 0; index < count; index += 1) {
        host.appendNode({
          id: `history-${index}`,
          revision: '1',
          body: { kind: 'message', author: 'agent', text: `token ${index}` }
        } as never)
      }
    }, HISTORY)
    await expect(
      page.getByTestId('conversation-scroll').locator(`[data-node-id="history-${HISTORY - 1}"]`)
    ).toBeAttached()

    // The stream: a fixed number of nodes in every animation frame, until it is stopped.
    await page.evaluate((perFrame) => {
      const host = window.krTestHost
      const keys = window.krKeys
      if (!host || !keys) throw new Error('the page is not ready to stream')
      let index = 0
      let running = true
      const scroll = document.querySelector('[data-testid="conversation-scroll"]')
      const tick = (): void => {
        if (!running) return
        for (let n = 0; n < perFrame; n += 1) {
          host.appendNode({
            id: `stream-${index}`,
            revision: '1',
            body: { kind: 'message', author: 'agent', text: `streamed ${index}` }
          } as never)
          index += 1
        }
        requestAnimationFrame(tick)
      }
      keys.stop = () => {
        running = false
      }
      // The newest streamed node in the conversation's window, which only moves while the stream
      // is being drawn: the window holds a bounded number of nodes, so a count would not.
      keys.drawn = () => {
        let newest = -1
        for (const drawn of scroll?.querySelectorAll('[data-node-id^="stream-"]') ?? []) {
          newest = Math.max(newest, Number(drawn.getAttribute('data-node-id')?.slice('stream-'.length)))
        }
        return newest
      }
      requestAnimationFrame(tick)
    }, PER_FRAME)
    // Typed only once the stream is being drawn, so that the readings are of keys against output
    // that is arriving, not before it has begun.
    await page.waitForFunction(() => (window.krKeys?.drawn() ?? -1) >= 0)
    const { times: streamed, drawnBefore, drawnAfter } = await typeKeys(page)
    await page.evaluate(() => window.krKeys?.stop())

    const typed = await page.getByTestId('composer-input').inputValue()
    const middle = { quiet: median(quiet), streamed: median(streamed) }
    const periods = middle.streamed / period
    const growth = middle.streamed / middle.quiet
    const machine = host()
    const figures = {
      engine,
      host: machine,
      framePeriodMs: period,
      keys: streamed.length,
      quiet: { medianMs: middle.quiet, p95Ms: percentile(quiet, 0.95), maxMs: Math.max(...quiet) },
      streaming: {
        medianMs: middle.streamed,
        p95Ms: percentile(streamed, 0.95),
        maxMs: Math.max(...streamed),
        medianFramePeriods: periods,
        growth
      },
      streamDrawnWhileTyping: [drawnBefore, drawnAfter]
    }
    await test.info().attach(`kr-perf-008-${engine}.json`, {
      body: JSON.stringify(figures, null, 2),
      contentType: 'application/json'
    })
    const verdict = periods <= REFERENCE_PERIODS && growth <= REFERENCE_GROWTH ? 'met' : 'missed'
    console.log(
      `KR-PERF-008 key to the second frame after it (${engine}): median ${middle.streamed.toFixed(1)} ms = ${periods.toFixed(1)} frame periods of ${period.toFixed(1)} ms ` +
        `with ${PER_FRAME} nodes a frame streaming over ${HISTORY}, p95 ${percentile(streamed, 0.95).toFixed(1)} ms, ` +
        `${growth.toFixed(2)}x the same keys with a short history and no stream (${verdict}); ` +
        `${machine.os}, ${machine.arch}, ${machine.processor}, ${machine.logicalProcessors} logical processors, ${machine.memoryMiB} MiB`
    )

    // Every key reached the composer, in order, and the stream advanced on the screen between the
    // moment the first key went in and the moment the last key's timing was read: a run where the keys finished before any of the stream
    // reached the screen would report the same figures and mean something else. The readings above
    // are recorded, and read by a person on a reference host.
    expect(typed).toBe(KEYS)
    expect(await page.evaluate(() => window.krKeys?.names.join('') ?? '')).toBe(KEYS)
    expect(streamed).toHaveLength(KEYS.length)
    expect(drawnAfter).toBeGreaterThan(drawnBefore)
  })
})
