/**
 * Asserts the voice surface, in the engine each platform actually renders it with.
 *
 * Every clause this file claims is a clause it checked on this run. It prints one `proved` line per
 * group of steps that passed, and one `unproved` line per clause it deliberately does not attempt;
 * the qualification log is built from those lines rather than from a fixed list. A step's words are
 * made by the function that makes the step, from fixed wording and the values it acts on or checks,
 * so a clause cannot say more than its steps did. A claim nothing measured is worse than no claim.
 *
 * The page is the harness: the real screen against the scripted host, which the harness publishes
 * as `window.krTestHost`. Every state below is set on that host, and the screen is only ever
 * observed drawing what the host and the call answered. A call screen is reached the way a person
 * reaches it, by pressing the start control.
 *
 * KR-REQ-15.09: managed content access disclosed in the provider choice.
 * KR-REQ-15.19: the provider and context scope shown before voice starts.
 * KR-REQ-15.36: muted or unavailable capture shown, with the statement that unheard speech never
 *   authorises. The refusal itself (KR-ACC-014) is not reachable from this screen, and is said so.
 * KR-REQ-15.17: local mute and closure survive broker failure.
 * KR-REQ-15.22: speech interruption stops playback only; cancellation is a separate host request.
 */

import { chromium, webkit, type Browser, type BrowserType, type Locator, type Page } from '@playwright/test'

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

/**
 * One thing done or seen. Its words are made by the function that makes the step, from fixed
 * wording and the very values the step acts on or checks, so a clause made of steps cannot say more
 * than the steps did.
 */
interface Step {
  readonly says: string
  readonly run: () => Promise<void>
}

/** Runs the steps in order and, when every one passes, records a proved line made of their words. */
async function prove(row: string, where: string, steps: readonly Step[]): Promise<void> {
  for (const step of steps) await step.run()
  const line = `proved ${row} | ${steps.map((step) => step.says).join('; ')} | ${where}`
  proved.push(line)
  console.log(line)
}

function unproved(row: string, clause: string, why: string): void {
  console.log(`unproved ${row} | ${clause} | ${why}`)
}

function expect(condition: boolean, message: string): void {
  if (!condition) throw new Error(message)
}

/** Words quoted as they were checked. */
function quoted(words: readonly string[]): string {
  return words.map((word) => `"${word}"`).join(', ')
}

/** Whitespace folded, so a sentence the layout wrapped still reads as the sentence. */
function folded(text: string): string {
  return text.replace(/\s+/g, ' ').trim()
}

/**
 * Waits until a visible element's visible text reads the whole of `text`. Elements are found by
 * their text and then held to what a person can see in them, so words in a hidden child do not
 * count toward the sentence.
 */
async function waitForText(page: Page, text: string): Promise<void> {
  const wanted = folded(text)
  const deadline = Date.now() + 5_000
  while (Date.now() < deadline) {
    const candidates = page.getByText(text, { exact: false })
    const count = await candidates.count()
    for (let index = 0; index < count; index += 1) {
      const candidate = candidates.nth(index)
      if ((await candidate.isVisible()) && folded(await candidate.innerText()).includes(wanted)) return
    }
    await page.waitForTimeout(100)
  }
  throw new Error(`no visible element read "${text}"`)
}

// ---- Things done -------------------------------------------------------------------------------

/** Opens the voice screen on a surface, with any starting state the address gives the host. */
function opening(page: Page, base: string, target: Target, query = ''): Step {
  return {
    says: query ? `the voice screen opened with "${query}"` : 'the voice screen opened',
    run: async () => {
      await page.goto(`${base}/harness.html?surface=${target.surface}&tab=voice${query}`)
      await page.waitForSelector('.kr-voice')
    }
  }
}

/** Presses the button with exactly this name. */
function pressing(page: Page, name: string): Step {
  return { says: `pressing "${name}"`, run: () => page.getByRole('button', { name, exact: true }).click() }
}

/** Calls one of the scripted host's controls, as the harness publishes them. */
function hostDoes(page: Page, control: string, ...args: readonly unknown[]): Step {
  return {
    says: `the scripted host's ${control}(${args.map((arg) => JSON.stringify(arg)).join(', ')})`,
    run: () =>
      page.evaluate(
        ({ control, args }) => {
          const controls = (window as unknown as { krTestHost: Record<string, (...a: unknown[]) => void> })
            .krTestHost
          controls[control](...args)
        },
        { control, args }
      )
  }
}

// ---- Things seen -------------------------------------------------------------------------------

function shows(page: Page, words: string): Step {
  return { says: `the page shows "${words}"`, run: () => waitForText(page, words) }
}

function button(page: Page, name: string): Step {
  return {
    says: `a "${name}" button`,
    run: () => page.getByRole('button', { name, exact: true }).waitFor({ timeout: 5_000 })
  }
}

/** No button whose name contains `part`, in any letter case, counting hidden ones as well. */
function noButton(page: Page, part: string): Step {
  return {
    says: `no button whose name contains "${part}", hidden or not`,
    run: async () => {
      const count = await page.getByRole('button', { name: part, includeHidden: true }).count()
      expect(count === 0, `found ${count} buttons whose name contains "${part}"`)
    }
  }
}

function heading(page: Page, name: string): Step {
  return {
    says: `the "${name}" heading`,
    run: () => page.getByRole('heading', { name, exact: true }).waitFor({ timeout: 5_000 })
  }
}

function noHeading(page: Page, name: string): Step {
  return {
    says: `no "${name}" heading, hidden or not`,
    run: async () => {
      const count = await page.getByRole('heading', { name, exact: true, includeHidden: true }).count()
      expect(count === 0, `found the "${name}" heading`)
    }
  }
}

/** The text a person can see in `locator`: it must be visible, and hidden descendants do not count. */
async function visibleText(locator: Locator, what: string): Promise<string> {
  await locator.waitFor({ state: 'visible', timeout: 5_000 }).catch(() => {
    throw new Error(`${what} is not visible`)
  })
  return locator.innerText()
}

/** The section labelled `region` is visible and its visible text carries every one of the words. */
function sectionShows(page: Page, region: string, words: readonly string[]): Step {
  return {
    says: `the "${region}" section shows ${quoted(words)}`,
    run: async () => {
      const text = await visibleText(page.getByRole('region', { name: region, exact: true }), `"${region}"`)
      for (const word of words) expect(text.includes(word), `"${region}" does not show "${word}": ${text}`)
    }
  }
}

function modelReads(page: Page, model: string): Step {
  return {
    says: `the voice model reads "${model}"`,
    run: async () => {
      const text = await visibleText(page.locator('.kr-voice__provider dd').first(), 'the voice model')
      expect(text.trim() === model, `the voice model reads "${text}"`)
    }
  }
}

/**
 * The button is described, through every id its `aria-describedby` names, by text carrying every one
 * of the words. An id that names nothing fails the step. This is what assistive technology reads,
 * whether or not it is on screen, and the words say so.
 */
function describedBy(page: Page, name: string, words: readonly string[]): Step {
  return {
    says: `the "${name}" button's aria-describedby text reads ${quoted(words)}`,
    run: async () => {
      const ids = ((await page.getByRole('button', { name, exact: true }).getAttribute('aria-describedby')) ?? '')
        .split(/\s+/)
        .filter((id) => id.length > 0)
      expect(ids.length > 0, `the "${name}" button names no description`)
      const texts = await page.evaluate(
        (names) => names.map((id) => document.getElementById(id)?.textContent ?? null),
        ids
      )
      expect(texts.every((text) => text !== null), `an id the "${name}" button names is on no element: ${ids.join(' ')}`)
      const described = texts.join(' ')
      for (const word of words) expect(described.includes(word), `the description does not show "${word}": ${described}`)
    }
  }
}

function captureReads(page: Page, words: string): Step {
  return {
    says: `the capture line reads "${words}"`,
    run: async () => {
      const line = page.locator('.kr-voice__capture').first()
      let actual = ''
      for (let attempt = 0; attempt < 50; attempt += 1) {
        actual = await visibleText(line, 'the capture line')
        if (actual.includes(words)) return
        await page.waitForTimeout(100)
      }
      throw new Error(`expected the capture line to read "${words}", got "${actual}"`)
    }
  }
}

function markedPressed(page: Page, name: string): Step {
  return {
    says: `"${name}" is marked pressed`,
    run: async () => {
      await page.waitForFunction(
        (label) =>
          [...document.querySelectorAll('button')]
            .find((element) => element.textContent === label)
            ?.getAttribute('aria-pressed') === 'true',
        name,
        { timeout: 5_000 }
      )
    }
  }
}

/** Each button passes every check a press makes (visible, enabled, steady, not covered), unpressed. */
function canPress(page: Page, names: readonly string[]): Step {
  return {
    says: `${quoted(names)} can be pressed`,
    run: async () => {
      for (const name of names) {
        await page.getByRole('button', { name, exact: true }).click({ trial: true, timeout: 5_000 })
      }
    }
  }
}

function cannotPress(page: Page, name: string): Step {
  return {
    says: `"${name}" cannot be pressed`,
    run: async () => {
      expect(await page.getByRole('button', { name, exact: true }).isDisabled(), `"${name}" can be pressed`)
    }
  }
}

function callOnScreen(page: Page, running: boolean): Step {
  return {
    says: running ? 'the running call is still on screen' : 'no running call is on the page',
    run: async () => {
      const calls = page.locator('.kr-voice--live')
      if (running) {
        expect((await calls.count()) === 1 && (await calls.isVisible()), 'the running call is not on screen')
      } else {
        expect((await calls.count()) === 0, 'a running call is still on the page')
      }
    }
  }
}

/** The named button sits in the section with this heading, and not among the call controls. */
function inOwnSection(page: Page, name: string, section: string): Step {
  return {
    says: `"${name}" sits under "${section}", and not among the call controls, hidden or not`,
    run: async () => {
      const panel = page.locator('section').filter({ has: page.getByRole('heading', { name: section, exact: true }) })
      expect((await panel.getByRole('button', { name, exact: true }).count()) === 1, `"${name}" is not under "${section}"`)
      const controls = page.getByRole('group', { name: 'Call controls', exact: true, includeHidden: true })
      expect((await controls.count()) === 1, 'the call controls are not on the page')
      const among = await controls.getByRole('button', { name, exact: true, includeHidden: true }).count()
      expect(among === 0, `"${name}" is among the call controls`)
    }
  }
}

function atLeastHigh(page: Page, name: string, minimum: number): Step {
  return {
    says: `the "${name}" button is at least ${minimum}px high`,
    run: async () => {
      const box = await page.getByRole('button', { name, exact: true }).boundingBox()
      expect((box?.height ?? 0) >= minimum, `"${name}" is ${box?.height ?? 0}px high`)
    }
  }
}

function everyCallControlAtLeastHigh(page: Page, minimum: number): Step {
  return {
    says: `every call control is at least ${minimum}px high`,
    run: async () => {
      const controls = page.locator('.kr-voice__control')
      const count = await controls.count()
      expect(count > 0, 'the call screen has no controls')
      for (let index = 0; index < count; index += 1) {
        const box = await controls.nth(index).boundingBox()
        expect((box?.height ?? 0) >= minimum, `control ${index} is ${box?.height ?? 0}px high`)
      }
    }
  }
}

// ---- What each surface is held to --------------------------------------------------------------

const DISCLOSURE = [
  'Audio travels directly between this device and the provider, not through this service.',
  "This service's own channel to the provider still receives transcripts",
  'is not a confirmation'
] as const
const SCOPE = ['the session', 'at most 8,000 tokens', 'the contents of files', 'raw terminal scrollback'] as const
const UNHEARD = 'Nothing spoken while the microphone was not carrying your voice can authorise an action'

async function assertProviderChoice(page: Page, base: string, target: Target): Promise<void> {
  const where = `${target.surface}/${target.engineName}`
  await prove('KR-REQ-15.09', where, [
    opening(page, base, target),
    button(page, 'Start voice session'),
    modelReads(page, 'gpt-live-1'),
    ...DISCLOSURE.map((line) => shows(page, line))
  ])
  await prove('KR-REQ-15.19', where, [
    sectionShows(page, 'Sessions this call can reach', ['Session 1']),
    sectionShows(page, 'What will be sent', SCOPE),
    sectionShows(page, 'What it costs', ['$0.01 a second', '$0.60 a minute']),
    describedBy(page, 'Start voice session', ['$0.01 a second', 'charged for at least 15 seconds'])
  ])
  await prove('KR-REQ-15.19', where, [
    opening(page, base, target, '&voice_terms=unread'),
    shows(page, "could not read the managed service's terms"),
    noButton(page, 'Start')
  ])
  await prove('KR-REQ-15.19', where, [
    opening(page, base, target, '&voice_terms=closed'),
    shows(page, 'Managed voice is closed at the moment'),
    shows(page, 'The coding agent already running on the host'),
    noButton(page, 'Start')
  ])
}

async function assertRateAndScope(page: Page, base: string, target: Target): Promise<void> {
  const where = `${target.surface}/${target.engineName}`
  await prove('KR-REQ-15.19', where, [
    opening(page, base, target),
    button(page, 'Start voice session'),
    hostDoes(page, 'changeVoiceRate', '2026-10-b', '3'),
    pressing(page, 'Start voice session'),
    shows(page, 'It is now $0.03 a second, and was $0.01'),
    sectionShows(page, 'What it costs', ['$0.03 a second', '$1.80 a minute']),
    noHeading(page, 'Voice session'),
    pressing(page, 'Start at the new rate'),
    heading(page, 'Voice session')
  ])
  await prove('KR-REQ-15.19', where, [
    opening(page, base, target),
    button(page, 'Start voice session'),
    hostDoes(page, 'changeVoiceScope'),
    pressing(page, 'Start voice session'),
    shows(page, 'changed after you read it, so nothing was started'),
    noHeading(page, 'Voice session'),
    pressing(page, 'Start voice session'),
    heading(page, 'Voice session')
  ])
}

async function assertCaptureStates(page: Page, base: string, target: Target): Promise<void> {
  const where = `${target.surface}/${target.engineName}`
  await prove('KR-REQ-15.36', where, [
    opening(page, base, target, '&voice_capture=unavailable'),
    pressing(page, 'Start voice session'),
    heading(page, 'Voice session'),
    captureReads(page, 'No microphone available'),
    shows(page, UNHEARD)
  ])
  await prove('KR-REQ-15.36', where, [
    hostDoes(page, 'setVoiceCapture', 'muted_by_person'),
    captureReads(page, 'Microphone muted'),
    shows(page, UNHEARD)
  ])
  await prove('KR-REQ-15.35', where, [
    hostDoes(page, 'setVoiceCapture', 'interrupted'),
    captureReads(page, 'Microphone taken by another call')
  ])
}

async function assertBrokerFailure(page: Page, base: string, target: Target): Promise<void> {
  const where = `${target.surface}/${target.engineName}`
  // Each control is pressed and held to what it changed: a control that is merely enabled proves
  // nothing, because it could be wired to nothing at all.
  await prove('KR-REQ-15.17', where, [
    opening(page, base, target),
    pressing(page, 'Start voice session'),
    heading(page, 'Voice session'),
    hostDoes(page, 'setVoiceBrokerReachable', false),
    shows(page, 'The voice service is not answering'),
    pressing(page, 'Mute microphone'),
    captureReads(page, 'Microphone muted'),
    pressing(page, 'Unmute microphone'),
    captureReads(page, 'Microphone on'),
    pressing(page, 'Stop the voice'),
    markedPressed(page, 'Stop the voice'),
    pressing(page, 'Show what the host selected'),
    shows(page, 'Selected by the host'),
    pressing(page, 'End session'),
    button(page, 'Start voice session'),
    callOnScreen(page, false)
  ])
  await prove('KR-REQ-15.17', where, [
    opening(page, base, target),
    pressing(page, 'Start voice session'),
    heading(page, 'Voice session'),
    hostDoes(page, 'setConnected', false),
    shows(page, 'This device is not reaching the host'),
    cannotPress(page, 'Show what the host selected'),
    canPress(page, ['Mute microphone', 'Stop the voice', 'End session'])
  ])
}

async function assertStopIsNotCancel(page: Page, base: string, target: Target): Promise<void> {
  const where = `${target.surface}/${target.engineName}`
  await prove('KR-REQ-15.22', where, [
    opening(page, base, target),
    pressing(page, 'Start voice session'),
    heading(page, 'Voice session'),
    pressing(page, 'Stop the voice'),
    markedPressed(page, 'Stop the voice'),
    captureReads(page, 'Microphone on'),
    callOnScreen(page, true),
    inOwnSection(page, 'Cancel the current turn', 'Cancel what the agent is doing'),
    cannotPress(page, 'Cancel the current turn'),
    shows(page, 'has not said which turn the agent is on')
  ])
}

async function assertTargetSize(page: Page, base: string, target: Target): Promise<void> {
  if (target.surface === 'desktop') return
  const where = `${target.surface}/${target.engineName}`
  const minimum = target.surface === 'android' ? 48 : 44
  await prove('KR-REQ-13 (section 13, line 879)', where, [
    opening(page, base, target),
    atLeastHigh(page, 'Start voice session', minimum),
    pressing(page, 'Start voice session'),
    heading(page, 'Voice session'),
    everyCallControlAtLeastHigh(page, minimum)
  ])
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

/** Fails unless `step` refuses the page it is given: a check that cannot fail proves nothing. */
async function refuses(page: Page, html: string, step: Step): Promise<void> {
  await page.setContent(html)
  let passed = true
  try {
    await step.run()
  } catch {
    passed = false
  }
  expect(!passed, `the check "${step.says}" passed on a page made to fail it`)
}

/**
 * The checks held to pages made to fail them, before any claim is made with them: words split
 * between visible and hidden text, and a hidden copy of a control among the call controls.
 */
async function checkTheChecks(): Promise<void> {
  const browser = await chromium.launch({ headless: true })
  try {
    const page = await browser.newPage()
    await refuses(
      page,
      '<p>The visible start <span style="display:none">and the hidden end</span></p>',
      shows(page, 'The visible start and the hidden end')
    )
    await refuses(
      page,
      '<section><h2>Cancel what the agent is doing</h2><button>Cancel the current turn</button></section>' +
        '<div role="group" aria-label="Call controls"><button aria-hidden="true">Cancel the current turn</button></div>',
      inOwnSection(page, 'Cancel the current turn', 'Cancel what the agent is doing')
    )
    await refuses(page, '<button aria-hidden="true">Start voice session</button>', noButton(page, 'Start'))
  } finally {
    await browser.close()
  }
  console.log('[assert-voice-surface] every check refused the page made to fail it')
}

async function main(): Promise<void> {
  const base = (process.argv[2] ?? 'http://localhost:4188').replace(/\/$/, '')
  await checkTheChecks()
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
  unproved(
    'KR-ACC-014',
    'a delegation claimed for speech the microphone did not carry is refused',
    'no provider channel reaches this screen, and the device record of when the microphone was on has no caller; only the statement the screen shows was checked'
  )

  console.log(`[assert-voice-surface] ${proved.length} clauses proved across ${TARGETS.length} targets`)
}

main().catch((error: unknown) => {
  console.error('[assert-voice-surface] FAILURE:', error)
  process.exitCode = 1
})
