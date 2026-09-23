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
 * What a person can see is read from the screen, never from the page's structure. Every step that
 * says something is on screen captures the place it is drawn and holds its claim to what the
 * system's text recognition reads there; the structure only says where to look and what state the
 * page is in. So no style, clip, cover, colour or animation can make a word count that is not drawn:
 * a word that is not drawn is not read. The picture is taken as the page draws it, with nothing
 * paused or changed, and its words are compared with the claim's whole and in order, so a longer
 * word or a moved decimal point is a different claim. What must be absent is counted in the
 * structure with hidden elements included, so a hidden copy fails the claim instead of passing it.
 * Before any claim, each check is given pages made to fail it and one made to pass it, and must
 * refuse the first and accept the second.
 *
 * Usage: `assert-voice-surface.ts <harness address> <text reader> <image directory>`. The text
 * reader prints the text it recognises in the image it is given; the one image being read is kept
 * in the directory, so the last one stays for whoever reads a failure.
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
declare const process: {
  readonly argv: readonly string[]
  exitCode?: number
  getBuiltinModule(id: 'node:child_process'): {
    execFileSync(file: string, args: readonly string[], options: { encoding: 'utf8'; timeout: number }): string
  }
}

/** The harness's address, the program that reads text in an image, and where the image goes. */
const [, , addressArgument, readerArgument, imagesArgument] = process.argv

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

/** Whitespace folded, so what was read prints on one line. */
function folded(text: string): string {
  return text.replace(/\s+/g, ' ').trim()
}

// ---- Reading the screen ------------------------------------------------------------------------

/** How long a step waits for the screen to draw what it expects. */
const PATIENCE_MS = 5_000

/** The text reader itself failed, which says nothing about the page and never counts as a refusal. */
class ReaderFailure extends Error {}

/**
 * The words of a text, in order: each run of letters and digits, in lower case. Spacing, line breaks
 * and punctuation only separate words, so a sentence the layout wrapped, an apostrophe drawn curly
 * or a comma the recogniser missed reads the same. Every word is compared whole and in its place:
 * "Unmute" is not "Mute", a sentence without its "not" is another sentence, and "0.01" (the words 0
 * and 01) is not "00.1" (00 and 1).
 */
function wordsOf(text: string): string[] {
  return text.normalize('NFKC').toLowerCase().match(/[\p{L}\p{N}]+/gu) ?? []
}

/** Whether all of `run`, a sequence of words, occurs together and in order in `read`. */
function includesRun(read: readonly string[], run: readonly string[]): boolean {
  if (run.length === 0) return false
  for (let start = 0; start + run.length <= read.length; start += 1) {
    if (run.every((word, offset) => read[start + offset] === word)) return true
  }
  return false
}

/**
 * Waits a little for every animation that ends to have ended, so a picture is not taken halfway
 * through a transition. Nothing on the page is changed to get there: an animation that never ends
 * is left running, and the picture shows it as a person sees it.
 */
async function settled(page: Page): Promise<void> {
  await page
    .waitForFunction(
      () =>
        document
          .getAnimations()
          .every(
            (animation) =>
              animation.playState !== 'running' || animation.effect?.getComputedTiming().endTime === Infinity
          ),
      undefined,
      { timeout: 2_000 }
    )
    .catch(() => undefined)
}

/** The text the system's text recognition reads in one image. */
function readImage(image: string): string {
  try {
    return process
      .getBuiltinModule('node:child_process')
      .execFileSync(readerArgument, [image], { encoding: 'utf8', timeout: 30_000 })
  } catch (error) {
    throw new ReaderFailure(`the text reader failed on ${image}: ${String(error)}`, { cause: error })
  }
}

/**
 * What a person can read in the one element `locator` names: the place is captured as the screen
 * draws it, animations included, and read by text recognition. Null while it is not one element on
 * screen.
 */
async function readOnScreen(locator: Locator): Promise<string | null> {
  const image = `${imagesArgument}/kr-voice-reading.png`
  await settled(locator.page())
  try {
    await locator.screenshot({ path: image, timeout: 1_000 })
  } catch {
    return null
  }
  return readImage(image)
}

/** Waits until the words read in `locator` pass `accept`, and fails with what was read. */
async function readUntil(
  locator: Locator,
  what: string,
  wanted: string,
  accept: (read: readonly string[]) => boolean
): Promise<void> {
  const deadline = Date.now() + PATIENCE_MS
  let last = 'nothing, because it was never on screen'
  do {
    const read = await readOnScreen(locator)
    if (read !== null) {
      if (accept(wordsOf(read))) return
      last = `"${folded(read)}"`
    }
    await locator.page().waitForTimeout(100)
  } while (Date.now() < deadline)
  throw new Error(`${what} never read ${wanted} on screen; it read ${last}`)
}

/** The place reads each of the phrases, every word whole and in order. */
function readsAll(locator: Locator, what: string, phrases: readonly string[]): Promise<void> {
  const wanted = phrases.map(wordsOf)
  return readUntil(locator, what, quoted(phrases), (read) => wanted.every((run) => includesRun(read, run)))
}

/**
 * Waits until an element carrying `text` is drawn so that the whole of it is read there. Elements are
 * found by the text they carry, which only says where to look: the claim is what was read.
 */
async function readSomewhere(page: Page, text: string): Promise<void> {
  const wanted = wordsOf(text)
  const deadline = Date.now() + PATIENCE_MS
  let last = 'nothing, because no element carrying it was on screen'
  do {
    const candidates = page.getByText(text, { exact: false })
    const count = await candidates.count()
    for (let index = 0; index < count; index += 1) {
      const read = await readOnScreen(candidates.nth(index))
      if (read === null) continue
      if (includesRun(wordsOf(read), wanted)) return
      last = `"${folded(read)}"`
    }
    await page.waitForTimeout(100)
  } while (Date.now() < deadline)
  throw new Error(`no element on screen read "${text}"; the last one read ${last}`)
}

/** Whether one box lies wholly inside another, to the half pixel. */
function inside(inner: Box, outer: Box): boolean {
  return (
    inner.x >= outer.x - 0.5 &&
    inner.y >= outer.y - 0.5 &&
    inner.x + inner.width <= outer.x + outer.width + 0.5 &&
    inner.y + inner.height <= outer.y + outer.height + 0.5
  )
}

/** Whether two boxes share any area. */
function overlap(one: Box, other: Box): boolean {
  return (
    one.x < other.x + other.width &&
    other.x < one.x + one.width &&
    one.y < other.y + other.height &&
    other.y < one.y + one.height
  )
}

/** Where an element is drawn on the page, in CSS pixels. */
interface Box {
  readonly x: number
  readonly y: number
  readonly width: number
  readonly height: number
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
  return { says: `the page shows "${words}"`, run: () => readSomewhere(page, words) }
}

/** A button with this name, whose name is drawn on it. */
function button(page: Page, name: string): Step {
  return {
    says: `a "${name}" button on screen`,
    run: () => readsAll(page.getByRole('button', { name, exact: true }), `the "${name}" button`, [name])
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
    says: `the "${name}" heading on screen`,
    run: () => readsAll(page.getByRole('heading', { name, exact: true }), `the "${name}" heading`, [name])
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

/** The section labelled `region` reads every one of the words on screen. */
function sectionShows(page: Page, region: string, words: readonly string[]): Step {
  return {
    says: `the "${region}" section shows ${quoted(words)}`,
    run: () => readsAll(page.getByRole('region', { name: region, exact: true }), `the "${region}" section`, words)
  }
}

/** The voice model reads this name on screen, and nothing else. */
function modelReads(page: Page, model: string): Step {
  const wanted = wordsOf(model)
  return {
    says: `the voice model reads "${model}"`,
    run: () =>
      readUntil(
        page.locator('.kr-voice__provider dd').first(),
        'the voice model',
        `"${model}"`,
        (read) => read.length === wanted.length && includesRun(read, wanted)
      )
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
    run: () => readsAll(page.locator('.kr-voice__capture').first(), 'the capture line', [words])
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

/**
 * Each button's name is drawn on it, and it passes every check a press makes (visible, enabled,
 * steady, not covered), unpressed.
 */
function canPress(page: Page, names: readonly string[]): Step {
  return {
    says: `${quoted(names)} on screen and can be pressed`,
    run: async () => {
      for (const name of names) {
        const control = page.getByRole('button', { name, exact: true })
        await readsAll(control, `the "${name}" button`, [name])
        await control.click({ trial: true, timeout: 5_000 })
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
    says: running
      ? 'the running call is still on screen, under its "Voice session" heading'
      : 'no running call is on the page, hidden or not',
    run: async () => {
      const calls = page.locator('.kr-voice--live')
      if (running) {
        expect((await calls.count()) === 1, 'the running call is not on the page')
        const title = calls.getByRole('heading', { name: 'Voice session', exact: true })
        await readsAll(title, 'the running call', ['Voice session'])
      } else {
        expect((await calls.count()) === 0, 'a running call is still on the page')
      }
    }
  }
}

/**
 * The named button belongs to the section with this heading, and both the heading and the button's
 * name are drawn; the button is drawn inside that section and clear of the call controls; and no
 * button of that name is among the call controls, hidden or not.
 */
function inOwnSection(page: Page, name: string, section: string): Step {
  return {
    says: `"${name}" is drawn inside "${section}", clear of the call controls, and is not among them, hidden or not`,
    run: async () => {
      const title = page.getByRole('heading', { name: section, exact: true })
      const panel = title.locator('xpath=ancestor::section[1]')
      expect((await panel.count()) === 1, `no section is headed "${section}"`)
      const own = panel.getByRole('button', { name, exact: true })
      expect((await own.count()) === 1, `"${name}" is not under "${section}"`)
      await readsAll(title, `the "${section}" heading`, [section])
      await readsAll(own, `the "${name}" button`, [name])
      const controls = page.getByRole('group', { name: 'Call controls', exact: true, includeHidden: true })
      expect((await controls.count()) === 1, 'the call controls are not on the page')
      const among = await controls.getByRole('button', { name, exact: true, includeHidden: true }).count()
      expect(among === 0, `"${name}" is among the call controls`)
      const [drawn, within, apart] = await Promise.all([own.boundingBox(), panel.boundingBox(), controls.boundingBox()])
      expect(drawn !== null && within !== null && inside(drawn, within), `"${name}" is not drawn inside "${section}"`)
      expect(drawn === null || apart === null || !overlap(drawn, apart), `"${name}" is drawn over the call controls`)
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

/**
 * Fails unless `step` refuses the page it is given: a check that cannot fail proves nothing. A
 * failure of the text reader is not a refusal, and ends the run.
 */
async function refuses(page: Page, html: string, step: Step): Promise<void> {
  await page.setContent(html)
  let passed = true
  try {
    await step.run()
  } catch (error) {
    if (error instanceof ReaderFailure) throw error
    passed = false
    console.log(`[assert-voice-surface] "${step.says}" refused ${html}: ${error instanceof Error ? error.message : String(error)}`)
  }
  expect(!passed, `the check "${step.says}" passed on a page made to fail it: ${html}`)
}

/** Fails unless `step` passes on the page it is given: a check that cannot pass proves nothing either. */
async function accepts(page: Page, html: string, step: Step): Promise<void> {
  await page.setContent(html)
  try {
    await step.run()
  } catch (error) {
    throw new Error(`the check "${step.says}" refused a page made to pass it: ${html}: ${String(error)}`, {
      cause: error
    })
  }
}

/** A sentence, and ways a page can keep its end from being drawn while the words stay in it. */
const SENTENCE = 'The visible start and the hidden end'
const HIDDEN_END: readonly string[] = [
  '<p>The visible start <span style="display:none">and the hidden end</span></p>',
  '<p>The visible start <span style="visibility:hidden">and the hidden end</span></p>',
  '<p>The visible start <span style="opacity:0">and the hidden end</span></p>',
  '<p>The visible start <span style="color:transparent">and the hidden end</span></p>',
  '<p style="background:#fff;color:#000">The visible start <span style="color:#fff">and the hidden end</span></p>',
  '<p>The visible start <span style="font-size:0">and the hidden end</span></p>',
  '<p>The visible start <span style="display:inline-block;transform:scale(0)">and the hidden end</span></p>',
  '<p>The visible start <span style="position:absolute;width:1px;height:1px;overflow:hidden;clip-path:inset(50%)">and the hidden end</span></p>',
  '<p>The visible start <span style="position:absolute;left:-10000px">and the hidden end</span></p>',
  '<p style="position:relative;display:inline-block">The visible start and the hidden end' +
    '<span style="position:absolute;top:0;right:0;bottom:0;width:50%;background:#fff"></span></p>',
  '<style>@keyframes kr-hidden { from, to { opacity: 0 } } .kr-hidden { animation: kr-hidden 1s infinite }</style>' +
    '<p>The visible start <span class="kr-hidden">and the hidden end</span></p>'
]

const CONTROLS = '<div role="group" aria-label="Call controls"><button>Stop the voice</button></div>'
const CANCEL_PANEL = '<section><h2>Cancel what the agent is doing</h2><button>Cancel the current turn</button></section>'

/**
 * Every check a claim is made with, held first to pages made to fail it and to a page made to pass
 * it, before any claim: a sentence whose end is not drawn in each way a page can manage that, an
 * animation that never ends among them; a section, a name, a capture line, a heading, a button and
 * a running call drawn transparent; a rate drawn with its decimal point moved, and a button named
 * "Mute" that draws "Unmute"; a cancellation drawn transparent, drawn over the call controls, or
 * copied among them hidden; and a start control or a call heading that is present but hidden.
 */
async function checkTheChecks(): Promise<void> {
  const browser = await chromium.launch({ headless: true })
  try {
    const page = await browser.newPage()

    const sentence = shows(page, SENTENCE)
    await accepts(page, `<p>${SENTENCE}</p>`, sentence)
    for (const html of HIDDEN_END) await refuses(page, html, sentence)

    const costs = sectionShows(page, 'What it costs', ['$0.01 a second'])
    await accepts(page, '<section aria-label="What it costs"><h2>What it costs</h2><p>$0.01 a second</p></section>', costs)
    await refuses(
      page,
      '<section aria-label="What it costs"><h2>What it costs</h2><p>$0.01 <span style="opacity:0">a second</span></p></section>',
      costs
    )
    await refuses(page, '<section aria-label="What it costs"><h2>What it costs</h2><p>$00.1 a second</p></section>', costs)

    const model = modelReads(page, 'gpt-live-1')
    await accepts(page, '<dl class="kr-voice__provider"><dt>Voice model</dt><dd>gpt-live-1</dd></dl>', model)
    await refuses(
      page,
      '<dl class="kr-voice__provider"><dt>Voice model</dt><dd>gpt-live-<span style="opacity:0">1</span></dd></dl>',
      model
    )

    const capture = captureReads(page, 'Microphone muted')
    await accepts(page, '<p class="kr-voice__capture">Microphone muted</p>', capture)
    await refuses(page, '<p class="kr-voice__capture">Microphone <span style="opacity:0">muted</span></p>', capture)

    const start = button(page, 'Start voice session')
    await accepts(page, '<button>Start voice session</button>', start)
    await refuses(page, '<button style="opacity:0">Start voice session</button>', start)

    const title = heading(page, 'Voice session')
    await accepts(page, '<h1>Voice session</h1>', title)
    await refuses(page, '<h1 style="opacity:0">Voice session</h1>', title)

    const live = callOnScreen(page, true)
    await accepts(page, '<section class="kr-voice--live"><h1>Voice session</h1></section>', live)
    await refuses(page, '<section class="kr-voice--live" style="opacity:0"><h1>Voice session</h1></section>', live)

    const ended = callOnScreen(page, false)
    await accepts(page, '<h1>Start a voice session</h1>', ended)
    await refuses(page, '<section class="kr-voice--live" style="display:none"><h1>Voice session</h1></section>', ended)

    const apart = inOwnSection(page, 'Cancel the current turn', 'Cancel what the agent is doing')
    await accepts(page, CONTROLS + CANCEL_PANEL, apart)
    await refuses(
      page,
      CONTROLS + CANCEL_PANEL.replace('<button>', '<button style="opacity:0">'),
      apart
    )
    await refuses(
      page,
      CONTROLS.replace('</div>', '<button aria-hidden="true">Cancel the current turn</button></div>') + CANCEL_PANEL,
      apart
    )
    await refuses(
      page,
      '<div role="group" aria-label="Call controls" style="height:60px"><button>Stop the voice</button></div>' +
        CANCEL_PANEL.replace('<button>', '<button style="position:absolute;top:16px;left:240px">'),
      apart
    )

    const pressable = canPress(page, ['Mute microphone'])
    await accepts(page, '<button>Mute microphone</button>', pressable)
    await refuses(page, '<button style="opacity:0">Mute microphone</button>', pressable)
    await refuses(page, '<button aria-label="Mute microphone">Unmute microphone</button>', pressable)

    const noStart = noButton(page, 'Start')
    await accepts(page, '<button>Mute microphone</button>', noStart)
    await refuses(page, '<button aria-hidden="true">Start voice session</button>', noStart)

    const noTitle = noHeading(page, 'Voice session')
    await accepts(page, '<h1>Start a voice session</h1>', noTitle)
    await refuses(page, '<h1 style="display:none">Voice session</h1>', noTitle)
  } finally {
    await browser.close()
  }
  console.log('[assert-voice-surface] every check refused each page made to fail it and passed the page made to pass it')
}

async function main(): Promise<void> {
  if (!readerArgument || !imagesArgument) {
    throw new Error(
      'usage: assert-voice-surface.ts <harness address> <text reader> <image directory>; ' +
        'what a person sees is read from the screen, so nothing is claimed without a text reader'
    )
  }
  const base = (addressArgument ?? 'http://localhost:4188').replace(/\/$/, '')
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
