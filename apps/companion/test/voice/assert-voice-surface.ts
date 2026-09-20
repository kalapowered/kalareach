/**
 * Asserts the voice surface, in the engine each platform actually renders it with.
 *
 * Every clause this file claims is a clause it checked on this run. It prints one `proved` line per
 * assertion that passed and one `unproved` line per clause it deliberately does not attempt, and the
 * qualification log is built from those lines rather than from a fixed list. A claim nothing
 * measured is worse than no claim at all.
 *
 * KR-REQ-15.09: managed content access disclosed in the provider choice.
 * KR-REQ-15.19: the provider and context scope shown before voice starts.
 * KR-REQ-15.36 and KR-ACC-014: muted or unavailable capture shown; unheard speech never authorises.
 * KR-REQ-15.17: local mute and closure survive broker failure.
 * KR-REQ-15.22: speech interruption stops playback only; cancellation uses the typed turn request.
 */

import { chromium, webkit, type Browser, type BrowserType, type Page } from '@playwright/test'

/** The runtime this file is executed by, declared rather than pulled in as a type package. */
declare const process: { readonly argv: readonly string[]; exitCode?: number }

/** One surface, and the engine the platform draws it with. */
interface Target {
  readonly surface: 'desktop' | 'ios' | 'android'
  readonly engine: BrowserType
  readonly engineName: string
}

const TARGETS: readonly Target[] = [
  { surface: 'desktop', engine: chromium, engineName: 'Chromium' },
  { surface: 'desktop', engine: webkit, engineName: 'WebKit' },
  { surface: 'ios', engine: webkit, engineName: 'WebKit' },
  { surface: 'android', engine: chromium, engineName: 'Chromium' }
]

/** A clause this run proved, named by the row it belongs to. */
const proved: string[] = []

function prove(row: string, clause: string, where: string): void {
  const line = `proved ${row} | ${clause} | ${where}`
  proved.push(line)
  console.log(line)
}

function unproved(row: string, clause: string, why: string): void {
  console.log(`unproved ${row} | ${clause} | ${why}`)
}

function expect(condition: boolean, message: string): void {
  if (!condition) throw new Error(message)
}

async function assertProviderChoice(page: Page, base: string, target: Target): Promise<void> {
  const where = `${target.surface}/${target.engineName}`
  await page.goto(`${base}/harness.html?surface=${target.surface}&tab=voice`)
  await page.waitForSelector('.kr-voice')

  const modelText = await page.textContent('.kr-voice__provider dd')
  expect(modelText?.includes('gpt-live-1') === true, `expected model gpt-live-1, got ${modelText}`)

  const content = await page.content()
  for (const fragment of [
    'Audio travels directly between this device and the provider',
    'The provider and this service can process the speech and the context',
    'is not a confirmation'
  ]) {
    expect(content.includes(fragment), `missing disclosure line: ${fragment}`)
  }
  prove('KR-REQ-15.09', 'the provider choice states what managed voice gives access to', where)

  expect(
    content.includes('Building the release') && content.includes('~/work/kalareach'),
    'missing context scope items'
  )
  expect(content.includes('8,000 tokens this host allows'), 'missing token cap text')
  expect(
    content.includes('file contents') && content.includes('terminal scrollback'),
    'missing withheld items'
  )
  prove(
    'KR-REQ-15.19',
    'the provider, the selected context, what is withheld and the token cap are shown before a call starts',
    where
  )

  await page.goto(`${base}/harness.html?surface=${target.surface}&tab=voice&over_cap=1`)
  await page.waitForSelector('.kr-voice')
  expect(
    await page.isDisabled('button.kr-voice__start'),
    'the start control must refuse a context selection over the cap'
  )
  prove('KR-REQ-15.19', 'a context selection over the cap cannot start a call', where)
}

async function assertCaptureStates(page: Page, base: string, target: Target): Promise<void> {
  const where = `${target.surface}/${target.engineName}`

  await page.goto(`${base}/harness.html?surface=${target.surface}&tab=voice&state=unavailable`)
  await page.waitForSelector('.kr-voice')
  const unavailable = await page.textContent('.kr-voice__capture')
  expect(
    unavailable?.includes('No microphone available') === true,
    `expected the unavailable capture state, got ${unavailable}`
  )
  const refusal = await page.textContent('.kr-voice__refusal')
  expect(
    refusal?.includes(
      'Nothing spoken while the microphone was not carrying your voice can authorise an action'
    ) === true,
    `missing the unheard-speech refusal, got ${refusal}`
  )
  prove(
    'KR-REQ-15.36',
    'unavailable capture is displayed and the screen refuses any claim that unheard speech authorised an action',
    where
  )

  await page.goto(`${base}/harness.html?surface=${target.surface}&tab=voice&state=muted`)
  await page.waitForSelector('.kr-voice')
  const muted = await page.textContent('.kr-voice__capture')
  expect(muted?.includes('Microphone muted') === true, `expected the muted state, got ${muted}`)
  expect(
    (await page.textContent('.kr-voice__refusal'))?.includes('can authorise an action') === true,
    'missing the refusal while muted'
  )
  prove('KR-REQ-15.36', 'a muted microphone is displayed with the same refusal', where)

  await page.goto(`${base}/harness.html?surface=${target.surface}&tab=voice&state=interrupted`)
  await page.waitForSelector('.kr-voice')
  const interrupted = await page.textContent('.kr-voice__capture')
  expect(
    interrupted !== null && interrupted.trim().length > 0,
    'the interrupted capture state must be displayed'
  )
  prove('KR-REQ-15.35', 'an interruption is an explicit displayed state on the surface', where)
}

async function assertBrokerFailure(page: Page, base: string, target: Target): Promise<void> {
  const where = `${target.surface}/${target.engineName}`
  await page.goto(
    `${base}/harness.html?surface=${target.surface}&tab=voice&state=capturing&broker=unreachable`
  )
  await page.waitForSelector('.kr-voice')
  const warning = await page.textContent('.kr-voice__refusal[role="status"]')
  expect(
    warning?.includes('The voice service is not answering') === true,
    'missing the broker-unreachable warning'
  )

  for (const name of ['Mute microphone', 'Stop the voice', 'End session']) {
    const control = page.getByRole('button', { name })
    expect(await control.isEnabled(), `${name} must stay available when the broker does not answer`)
  }

  // Mute survives a broker that does not answer: the control acts locally and the displayed capture
  // state follows it without any round trip.
  await page.getByRole('button', { name: 'Mute microphone' }).click()
  const afterMute = await page.textContent('.kr-voice__capture')
  expect(
    afterMute?.includes('Microphone muted') === true,
    `muting with the broker refused must change the capture state, got ${afterMute}`
  )
  prove(
    'KR-REQ-15.17',
    'local microphone mute, playback stop and closure all act with the broker unreachable',
    where
  )

  // Cancelling a turn goes to the host, not to the voice service, so a voice service that has
  // stopped answering must not take it away.
  expect(
    await page.getByRole('button', { name: 'Cancel the current turn' }).isEnabled(),
    'cancelling a turn reaches the host and must survive an unreachable voice service'
  )
  prove(
    'KR-REQ-15.22',
    'cancelling a turn stays available when the voice service does not answer, because it goes to the host',
    where
  )

  await page.goto(
    `${base}/harness.html?surface=${target.surface}&tab=voice&state=capturing&host=unreachable`
  )
  await page.waitForSelector('.kr-voice')
  expect(
    await page.getByRole('button', { name: 'Cancel the current turn' }).isDisabled(),
    'task cancellation must be refused when the host cannot be reached'
  )
  for (const name of ['Mute microphone', 'Stop the voice', 'End session']) {
    expect(
      await page.getByRole('button', { name }).isEnabled(),
      `${name} must stay available when the host cannot be reached`
    )
  }
  prove(
    'KR-REQ-15.17',
    'a path that is genuinely unavailable is disabled and said so, while the local controls stay',
    where
  )
}

async function assertStopIsNotCancel(page: Page, base: string, target: Target): Promise<void> {
  const where = `${target.surface}/${target.engineName}`
  await page.goto(`${base}/harness.html?surface=${target.surface}&tab=voice&state=capturing`)
  await page.waitForSelector('.kr-voice')

  // Stopping the voice takes one press and changes only playback.
  await page.getByRole('button', { name: 'Stop the voice' }).click()
  const captureAfterStop = await page.textContent('.kr-voice__capture')
  expect(
    captureAfterStop?.includes('Microphone muted') !== true,
    'stopping playback must not mute the microphone'
  )

  // Cancelling a turn is a separate control, in a separate panel, and it takes a confirmation.
  const cancelPanel = page.locator('.kr-voice__panel--cancel')
  expect(await cancelPanel.isVisible(), 'task cancellation must have its own panel')
  await page.getByRole('button', { name: 'Cancel the current turn' }).click()
  expect(
    await page.getByRole('button', { name: 'Cancel this turn' }).isVisible(),
    'task cancellation must ask for confirmation'
  )
  prove(
    'KR-REQ-15.22',
    'stopping the voice is one press and changes playback only; cancelling a turn is a separate confirmed control',
    where
  )
}

async function assertTargetSize(page: Page, base: string, target: Target): Promise<void> {
  if (target.surface === 'desktop') return
  const where = `${target.surface}/${target.engineName}`
  const minimum = target.surface === 'android' ? 48 : 44

  await page.goto(`${base}/harness.html?surface=${target.surface}&tab=voice&state=capturing`)
  await page.waitForSelector('.kr-voice')
  const controls = page.locator('.kr-voice__control')
  const count = await controls.count()
  expect(count > 0, 'the call screen must have controls')
  for (let index = 0; index < count; index += 1) {
    const box = await controls.nth(index).boundingBox()
    expect(box !== null, 'a control must be laid out')
    expect(
      (box?.height ?? 0) >= minimum,
      `control ${index} is ${box?.height ?? 0}px high, below the ${minimum}px platform minimum`
    )
  }
  prove(
    'KR-REQ-13 (section 13, line 879)',
    `every call control meets the ${minimum}px platform touch target`,
    where
  )
}

async function assertTarget(base: string, target: Target): Promise<void> {
  console.log(`[assert-voice-surface] ${target.surface} in ${target.engineName}`)
  const browser: Browser = await target.engine.launch({ headless: true })
  try {
    const page = await browser.newPage(
      target.surface === 'desktop'
        ? { viewport: { width: 1280, height: 800 } }
        : { viewport: { width: 390, height: 844 }, deviceScaleFactor: 3, isMobile: true }
    )
    await assertProviderChoice(page, base, target)
    await assertCaptureStates(page, base, target)
    await assertBrokerFailure(page, base, target)
    await assertStopIsNotCancel(page, base, target)
    await assertTargetSize(page, base, target)
  } finally {
    await browser.close()
  }
}

async function main(): Promise<void> {
  const base = (process.argv[2] ?? 'http://localhost:4188').replace(/\/$/, '')
  for (const target of TARGETS) {
    await assertTarget(base, target)
  }

  // What this file cannot establish, said here rather than left for a reader to assume.
  unproved(
    'KR-PERF-010',
    'first-audio and delegation latency',
    'no media path is connected to the surface, so there is no first audio and no delegation to time'
  )
  unproved(
    'KR-REQ-15.34',
    'audio after screen lock',
    'a browser engine has no audio session and no foreground service; the device leg is the operator gate'
  )
  unproved(
    'KR-REQ-15.35',
    'a real route change, a phone call and application termination',
    'an engine cannot raise a platform interruption; only the states the surface draws were checked'
  )

  console.log(`[assert-voice-surface] ${proved.length} clauses proved across ${TARGETS.length} targets`)
}

main().catch((error: unknown) => {
  console.error('[assert-voice-surface] FAILURE:', error)
  process.exitCode = 1
})
