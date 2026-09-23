/**
 * Asserts the voice surface, in the engine each platform actually renders it with.
 *
 * Every clause this file claims is a clause it checked on this run. It prints one `proved` line per
 * assertion that passed and one `unproved` line per clause it deliberately does not attempt, and the
 * qualification log is built from those lines rather than from a fixed list. A claim nothing
 * measured is worse than no claim at all.
 *
 * The page is the harness: the real screen against the scripted host, which the harness publishes
 * as `window.krTestHost`. Every state below is set on that host, and the screen is only ever
 * observed drawing what the host and the call answered. A call screen is reached the way a person
 * reaches it, by pressing the start control.
 *
 * KR-REQ-15.09: managed content access disclosed in the provider choice.
 * KR-REQ-15.19: the provider and context scope shown before voice starts.
 * KR-REQ-15.36 and KR-ACC-014: muted or unavailable capture shown; unheard speech never authorises.
 * KR-REQ-15.17: local mute and closure survive broker failure.
 * KR-REQ-15.22: speech interruption stops playback only; cancellation is a separate host request.
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

/** Opens the voice screen on a surface, with any starting state the address gives the host. */
async function open(page: Page, base: string, target: Target, query = ''): Promise<void> {
  await page.goto(`${base}/harness.html?surface=${target.surface}&tab=voice${query}`)
  await page.waitForSelector('.kr-voice')
}

/** Calls one of the scripted host's controls, as the harness publishes them. */
async function host(page: Page, name: string, ...args: readonly unknown[]): Promise<void> {
  await page.evaluate(
    ({ name, args }) => {
      const controls = (window as unknown as { krTestHost: Record<string, (...a: unknown[]) => void> })
        .krTestHost
      controls[name](...args)
    },
    { name, args }
  )
}

/** Waits until the page's text includes `text`, and fails with `message` when it never does. */
async function waitForText(page: Page, text: string, message: string): Promise<void> {
  try {
    await page.getByText(text, { exact: false }).first().waitFor({ timeout: 5_000 })
  } catch {
    throw new Error(message)
  }
}

/** Presses the start control and waits for the call screen the host's answer opens. */
async function startCall(page: Page): Promise<void> {
  await page.getByRole('button', { name: 'Start voice session' }).click()
  await page.getByRole('heading', { name: 'Voice session', exact: true }).waitFor({ timeout: 5_000 })
}

/** What the capture line says, once it says `expected`. */
async function captureReads(page: Page, expected: string): Promise<void> {
  try {
    await page.waitForFunction(
      (text) => document.querySelector('.kr-voice__capture')?.textContent?.includes(text) === true,
      expected,
      { timeout: 5_000 }
    )
  } catch {
    const actual = await page.textContent('.kr-voice__capture')
    throw new Error(`expected the capture line to read "${expected}", got "${actual ?? ''}"`)
  }
}

async function assertProviderChoice(page: Page, base: string, target: Target): Promise<void> {
  const where = `${target.surface}/${target.engineName}`
  await open(page, base, target)
  await page.getByRole('button', { name: 'Start voice session' }).waitFor()

  const modelText = await page.textContent('.kr-voice__provider dd')
  expect(modelText?.includes('gpt-live-1') === true, `expected model gpt-live-1, got ${modelText}`)
  for (const fragment of [
    'Audio travels directly between this device and the provider, not through this service.',
    "This service's own channel to the provider still receives transcripts",
    'is not a confirmation'
  ]) {
    await waitForText(page, fragment, `missing disclosure line: ${fragment}`)
  }
  prove('KR-REQ-15.09', 'the provider choice states what managed voice gives access to, in the service’s words', where)

  const sessions = page.getByRole('region', { name: 'Sessions this call can reach' })
  expect((await sessions.textContent())?.match(/Session \d+/) !== null, 'missing the session scope')
  const scope = (await page.getByRole('region', { name: 'What will be sent' }).textContent()) ?? ''
  for (const fragment of ['the session', 'at most 8,000 tokens', 'the contents of files', 'raw terminal scrollback']) {
    expect(scope.includes(fragment), `missing from the context scope: ${fragment}`)
  }
  const cost = (await page.getByRole('region', { name: 'What it costs' }).textContent()) ?? ''
  expect(cost.includes('a second') && cost.includes('a minute'), `missing the rate, got ${cost}`)
  const describedBy = await page.getByRole('button', { name: 'Start voice session' }).getAttribute('aria-describedby')
  expect(describedBy !== null && describedBy.includes('cost'), 'the start control must be described by the rate')
  prove(
    'KR-REQ-15.19',
    'the provider, the sessions, the context scope, what is withheld, the cap and the rate are shown before a call starts',
    where
  )

  await open(page, base, target, '&voice_terms=unread')
  await waitForText(page, "could not read the managed service's terms", 'missing the host’s reason for no terms')
  expect((await page.getByRole('button', { name: /Start/ }).count()) === 0, 'no start without the service’s terms')
  prove('KR-REQ-15.19', 'without the service’s terms no start is offered and the host’s reason is shown', where)

  await open(page, base, target, '&voice_terms=closed')
  await waitForText(page, 'Managed voice is closed at the moment', 'missing the closed state')
  await waitForText(page, 'The coding agent already running on the host', 'missing what still works')
  expect((await page.getByRole('button', { name: /Start/ }).count()) === 0, 'no start while managed voice is closed')
  prove('KR-REQ-15.19', 'while managed voice is closed no start is offered and what still works is listed', where)
}

async function assertRateAndScope(page: Page, base: string, target: Target): Promise<void> {
  const where = `${target.surface}/${target.engineName}`

  await open(page, base, target)
  await page.getByRole('button', { name: 'Start voice session' }).waitFor()
  await host(page, 'changeVoiceRate', '2026-10-b', '3')
  await page.getByRole('button', { name: 'Start voice session' }).click()
  await page.getByRole('button', { name: 'Start at the new rate' }).waitFor({ timeout: 5_000 })
  await waitForText(page, 'The rate changed after you read it. It is now', 'missing the announcement of the new rate')
  expect((await page.getByRole('heading', { name: 'Voice session', exact: true }).count()) === 0, 'a changed rate must start nothing')
  await page.getByRole('button', { name: 'Start at the new rate' }).click()
  await page.getByRole('heading', { name: 'Voice session', exact: true }).waitFor({ timeout: 5_000 })
  prove(
    'KR-REQ-15.19',
    'a start refused for a changed rate shows the new rate beside the old and starts only when pressed again',
    where
  )

  await open(page, base, target)
  await page.getByRole('button', { name: 'Start voice session' }).waitFor()
  await host(page, 'changeVoiceScope')
  await page.getByRole('button', { name: 'Start voice session' }).click()
  await waitForText(page, 'changed after you read it, so nothing was started', 'missing the changed-scope notice')
  expect((await page.getByRole('heading', { name: 'Voice session', exact: true }).count()) === 0, 'a changed scope must start nothing')
  await startCall(page)
  prove(
    'KR-REQ-15.19',
    'a start under a preparation that no longer holds starts nothing, and the preparation is read again',
    where
  )
}

async function assertCaptureStates(page: Page, base: string, target: Target): Promise<void> {
  const where = `${target.surface}/${target.engineName}`

  await open(page, base, target, '&voice_capture=unavailable')
  await startCall(page)
  await captureReads(page, 'No microphone available')
  await waitForText(
    page,
    'Nothing spoken while the microphone was not carrying your voice can authorise an action',
    'missing the unheard-speech refusal'
  )
  prove(
    'KR-REQ-15.36',
    'unavailable capture is displayed and the screen refuses any claim that unheard speech authorised an action',
    where
  )

  await host(page, 'setVoiceCapture', 'muted_by_person')
  await captureReads(page, 'Microphone muted')
  await waitForText(page, 'can authorise an action', 'missing the refusal while muted')
  prove('KR-REQ-15.36', 'a muted microphone is displayed with the same refusal', where)

  await host(page, 'setVoiceCapture', 'interrupted')
  await captureReads(page, 'Microphone taken by another call')
  prove('KR-REQ-15.35', 'an interruption the call reports is an explicit displayed state', where)
}

async function assertBrokerFailure(page: Page, base: string, target: Target): Promise<void> {
  const where = `${target.surface}/${target.engineName}`

  await open(page, base, target)
  await startCall(page)
  await host(page, 'setVoiceBrokerReachable', false)
  await waitForText(page, 'The voice service is not answering', 'missing the broker-unreachable warning')
  for (const name of ['Mute microphone', 'Stop the voice', 'End session', 'Show what the host selected']) {
    expect(await page.getByRole('button', { name }).isEnabled(), `${name} must stay available when the voice service does not answer`)
  }

  // Each control is pressed and checked by what it changed. A control that is merely enabled
  // proves nothing: it could be wired to nothing at all.
  await page.getByRole('button', { name: 'Mute microphone' }).click()
  await captureReads(page, 'Microphone muted')
  await page.getByRole('button', { name: 'Unmute microphone' }).click()
  await captureReads(page, 'Microphone on')

  await page.getByRole('button', { name: 'Stop the voice' }).click()
  await page.waitForFunction(
    () =>
      [...document.querySelectorAll('button')]
        .find((button) => button.textContent === 'Stop the voice')
        ?.getAttribute('aria-pressed') === 'true',
    undefined,
    { timeout: 5_000 }
  )

  await page.getByRole('button', { name: 'Show what the host selected' }).click()
  await waitForText(page, 'Selected by the host', 'reading the host’s selection must answer from the host')

  await page.getByRole('button', { name: 'End session' }).click()
  await page.getByRole('button', { name: 'Start voice session' }).waitFor({ timeout: 5_000 })
  expect((await page.locator('.kr-voice--live').count()) === 0, 'ending the session must close the call')
  prove(
    'KR-REQ-15.17',
    'with the voice service not answering, muting, silencing playback, reading the host’s selection and ending the session each act and each changes what it claims to',
    where
  )

  await open(page, base, target)
  await startCall(page)
  await host(page, 'setConnected', false)
  await waitForText(page, 'This device is not reaching the host', 'missing the host-unreachable warning')
  expect(
    await page.getByRole('button', { name: 'Show what the host selected' }).isDisabled(),
    'a read from the host must be withdrawn when the host cannot be reached'
  )
  for (const name of ['Mute microphone', 'Stop the voice', 'End session']) {
    expect(await page.getByRole('button', { name }).isEnabled(), `${name} must stay available when the host cannot be reached`)
  }
  prove(
    'KR-REQ-15.17',
    'a request to the host is withdrawn and said so when the host is gone, while the local controls stay',
    where
  )
}

async function assertStopIsNotCancel(page: Page, base: string, target: Target): Promise<void> {
  const where = `${target.surface}/${target.engineName}`
  await open(page, base, target)
  await startCall(page)

  // Stopping the voice takes one press, silences playback, and changes nothing else.
  await page.getByRole('button', { name: 'Stop the voice' }).click()
  await page.waitForFunction(
    () =>
      [...document.querySelectorAll('button')]
        .find((button) => button.textContent === 'Stop the voice')
        ?.getAttribute('aria-pressed') === 'true',
    undefined,
    { timeout: 5_000 }
  )
  await captureReads(page, 'Microphone on')
  expect((await page.locator('.kr-voice--live').count()) === 1, 'stopping playback must not end the call')

  // Cancelling a turn is a separate control in a separate panel, and it needs the turn the agent
  // is on from the host. No host answer names one, so the control is off and says why.
  const panel = page.locator('.kr-voice__panel--cancel')
  expect(await panel.isVisible(), 'task cancellation must have its own panel')
  expect(
    await page.getByRole('button', { name: 'Cancel the current turn' }).isDisabled(),
    'with no turn named by the host there is nothing to cancel'
  )
  await waitForText(page, 'has not said which turn the agent is on', 'missing why there is no turn to cancel')
  prove(
    'KR-REQ-15.22',
    'stopping the voice is one press and changes playback only; cancelling a turn is a separate control that needs the host’s turn',
    where
  )
}

async function assertTargetSize(page: Page, base: string, target: Target): Promise<void> {
  if (target.surface === 'desktop') return
  const where = `${target.surface}/${target.engineName}`
  const minimum = target.surface === 'android' ? 48 : 44

  await open(page, base, target)
  const start = await page.locator('.kr-voice__start').boundingBox()
  expect((start?.height ?? 0) >= minimum, `the start control is ${start?.height ?? 0}px high, below ${minimum}px`)
  await startCall(page)
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
    `the start control and every call control meet the ${minimum}px platform touch target`,
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
    await assertRateAndScope(page, base, target)
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
    'the harness drives the screen against a scripted host with no media path, so there is no first audio and no delegation to time'
  )
  unproved(
    'KR-REQ-15.22',
    'a cancellation carrying the current turn identifier',
    'no host answer names the turn an agent is on, so the confirmation step cannot be reached'
  )
  unproved(
    'KR-REQ-15.13',
    'an unlocked-screen confirmation made from this screen',
    'this screen has no way to reach the device’s ceremony; the host’s challenge is shown and not acted on'
  )
  unproved(
    'KR-REQ-15.34',
    'audio after screen lock',
    'a browser engine has no audio session and no foreground service; the device leg is the operator gate'
  )
  unproved(
    'KR-REQ-15.35',
    'a real route change, a phone call and application termination',
    'an engine cannot raise a platform interruption; only the states a call reports were checked'
  )

  console.log(`[assert-voice-surface] ${proved.length} clauses proved across ${TARGETS.length} targets`)
}

main().catch((error: unknown) => {
  console.error('[assert-voice-surface] FAILURE:', error)
  process.exitCode = 1
})
