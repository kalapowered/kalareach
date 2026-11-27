/**
 * How long anything in the interface moves, as a browser engine reads the stylesheets.
 *
 * Section 13 gives the interface one range for motion: default transitions last 120 to 200 ms, and
 * a keyboard command or streamed text is not animated at all. The other browser tests check what a
 * person sees for the keyboard and for streamed text. This one reads every motion declaration the
 * way the engine does: the engine parses the stylesheets, and every block of declarations it parsed
 * is visited, nested and imported ones included. A declaration's durations are read from the
 * declaration alone, as the engine writes it back once it is set on an element outside the
 * document, so a comment or a time in any CSS form is read exactly as the engine reads it, rather
 * than by a second parser here, and no other rule on the page changes the reading.
 *
 * A declaration is read only when every element reads it the same way. The engine settles that for
 * a declaration without variables or other substitutions: its duration must be a plain list of
 * times once parsed, which no element can read differently. Otherwise the declaration must be
 * written in the one form the interface uses, a property or animation name, a duration token and
 * an optional easing, every token it names must be set by the top-level document root and by
 * nothing else, and each token's value there must itself be one plain value of its kind, a time for
 * the duration and an easing function for the easing. Every element then substitutes the one value
 * the root holds, which is the time read, and each item written stays one item. Anything else is
 * refused, whatever it is, rather than read.
 *
 * The same reading runs over each built bundle, where the terminal's own stylesheet comes with the
 * application's. A declaration there that is outside the range counts only when it never reaches
 * an element, because an important declaration overrides it on every element it could apply to.
 */

import { readFileSync, readdirSync } from 'node:fs'

import { expect, test, type Locator, type Page } from '@playwright/test'

import { PRESENTATION_DEADLINE } from './bounds'
import { DESKTOP_BUNDLE } from './served'

/** Every stylesheet under `src`, the design tokens first so their variables are defined. */
function ownStylesheets(): Array<{ file: string; text: string }> {
  const root = new URL('../src/', import.meta.url)
  return readdirSync(root, { recursive: true })
    .map((file) => file.replaceAll('\\', '/'))
    .filter((file) => file.endsWith('.css'))
    .sort((a, b) => Number(!a.endsWith('tokens.css')) - Number(!b.endsWith('tokens.css')))
    .map((file) => ({ file, text: readFileSync(new URL(file, root), 'utf8') }))
}

/** One motion declaration, and its durations in seconds or why they could not be read. */
interface Declared {
  readonly where: string
  readonly property: string
  readonly value: string
  readonly seconds: number[] | string
  /** Whether an important declaration of the same duration overrides it wherever it applies. */
  readonly overridden: boolean
}

/**
 * Reads every motion declaration of the stylesheets `from` onwards in the page's document list.
 *
 * Runs in the page. Every rule the engine parsed is visited, and a rule is read when it holds a
 * block of declarations of its own, whatever kind of rule it is.
 */
async function motionIn(
  page: Page,
  from: number
): Promise<{ rules: number; adopted: number; declared: Declared[] }> {
  return page.evaluate((first) => {
    const MOTION = ['transition', 'transition-duration', 'animation', 'animation-duration']
    const longhandOf = (property: string): string =>
      property.startsWith('transition') ? 'transition-duration' : 'animation-duration'

    // Where every variable is set, and whether that place is the document root outside any
    // condition. Read from every stylesheet in the document, not only the ones being checked.
    const setAt = new Map<string, Array<{ where: string; atRoot: boolean }>>()
    const found: Array<{ where: string; property: string; value: string; rule: CSSRule }> = []
    // The top-level rules of the stylesheets that apply unconditionally: the only rules whose
    // important declaration is taken to override another wherever that one applies.
    const unconditional: CSSStyleRule[] = []
    // A namespace changes what a selector's text matches, so the text alone would not say which
    // elements two rules share.
    let namespaced = false
    let rules = 0
    // A block of declarations nested inside a style rule is named by that rule's selector, so a
    // declaration is named the same way whether the engine keeps it in its own block or not.
    const visit = (list: CSSRuleList, depth: number, reading: boolean, within: string): void => {
      for (const rule of Array.from(list)) {
        if (reading) rules += 1
        if (rule instanceof CSSNamespaceRule) namespaced = true
        const where =
          rule instanceof CSSStyleRule
            ? rule.selectorText
            : within !== ''
              ? within
              : rule.cssText.slice(0, 60)
        if (rule.constructor.name === 'CSSPropertyRule') {
          const name = (rule as unknown as { name: string }).name
          setAt.set(name, [...(setAt.get(name) ?? []), { where: '@property', atRoot: false }])
        }
        const style = (rule as unknown as { style?: unknown }).style
        if (style instanceof CSSStyleDeclaration) {
          const atRoot =
            depth === 0 && rule instanceof CSSStyleRule && rule.selectorText === ':root'
          for (let index = 0; index < style.length; index += 1) {
            const name = style.item(index)
            if (name.startsWith('--')) {
              setAt.set(name, [...(setAt.get(name) ?? []), { where, atRoot }])
            }
          }
          if (reading) {
            for (const property of MOTION) {
              const value = style.getPropertyValue(property)
              if (value !== '') found.push({ where, property, value, rule })
            }
          }
        }
        if (depth === 0 && rule instanceof CSSStyleRule) {
          const sheet = rule.parentStyleSheet
          if (sheet && sheet.ownerRule === null && sheet.media.length === 0 && !sheet.disabled) {
            unconditional.push(rule)
          }
        }
        // An imported stylesheet is read as part of the one that imports it.
        const children =
          rule instanceof CSSImportRule
            ? rule.styleSheet?.cssRules
            : (rule as unknown as { cssRules?: unknown }).cssRules
        if (children instanceof CSSRuleList) {
          visit(children, depth + 1, reading, rule instanceof CSSStyleRule ? where : within)
        }
      }
    }
    Array.from(document.styleSheets).forEach((sheet, index) => {
      visit(sheet.cssRules, 0, index >= first, '')
    })

    // The one written form a declaration that uses variables may take: per item, a property or
    // animation name, a duration token, an optional easing token or keyword and an optional delay
    // written as a plain time.
    const EASING = [
      String.raw`var\((--ease-out|--ease-in-out)\)`,
      'ease',
      'linear',
      'ease-in',
      'ease-out',
      'ease-in-out'
    ].join('|')
    const DURATION = String.raw`var\((--press|--state|--surface-in)\)`
    const TIME = String.raw`\d+(?:\.\d+)?m?s`
    const ITEM = new RegExp(
      String.raw`^[a-z][a-z0-9-]*\s+${DURATION}(?:\s+(?:${EASING}))?(?:\s+${TIME})?$`
    )
    const ALONE = new RegExp(`^${DURATION}$`)
    // How the engine writes a list of durations it parsed with no context: nothing but times, or
    // `auto`, which a time-based animation reads as zero.
    const PLAIN = new RegExp(`^(?:auto|${TIME})(?:, (?:auto|${TIME}))*$`)
    // How the engine writes one time, and one easing function, it parsed with no context.
    const ONE_TIME = new RegExp(`^${TIME}$`)
    const NUMBER = String.raw`-?(?:\d+(?:\.\d+)?|\.\d+)(?:e[+-]?\d+)?`
    const ONE_EASING = new RegExp(
      String.raw`^(?:ease|linear|ease-in|ease-out|ease-in-out|cubic-bezier\(${NUMBER}, ${NUMBER}, ${NUMBER}, ${NUMBER}\))$`
    )
    // How the engine writes `longhand` of a declaration it parsed on an element outside the
    // document, which no rule of the page reaches and which has nothing to inherit.
    const scratch = document.createElement('div')
    const written = (property: string, value: string, longhand: string): string => {
      scratch.removeAttribute('style')
      scratch.style.setProperty(property, value)
      return scratch.style.getPropertyValue(longhand)
    }
    // The one plain value of its kind the root holds for a token, as the engine writes it, or why
    // there is none. What the engine writes back has to be the one value: a value it keeps
    // unparsed until an element uses it could be read differently by every element, and a list or a
    // second item would add to the declaration it is substituted into.
    const rootValue = (
      name: string,
      longhand: string,
      form: RegExp,
      kind: string
    ): { value: string } | { refused: string } => {
      const held = getComputedStyle(document.documentElement).getPropertyValue(name).trim()
      const value = written(longhand, held, longhand)
      return form.test(value)
        ? { value }
        : { refused: `${name} is not a plain ${kind} at the root: ${held}` }
    }
    // Seconds, from one time as the engine writes it; `auto` is zero for a time-based animation.
    const seconds = (time: string): number => {
      const text = time.trim()
      if (text === 'auto') return 0
      const amount = Number.parseFloat(text)
      return text.endsWith('ms') ? amount / 1000 : amount
    }
    // A declaration's durations, read from the declaration alone and never from an element in the
    // page, where other rules decide what reaches it. A declaration in plain times is read from how
    // the engine writes it; one in the interface's form takes each item's time from the duration
    // token the root holds, which is what every element substitutes.
    const measure = (property: string, value: string): number[] | string => {
      const longhand = longhandOf(property)
      const form = property === longhand ? ALONE : ITEM
      const items = value.split(',').map((item) => form.exec(item.trim()))
      if (items.every((item) => item !== null)) {
        const durations: number[] = []
        for (const item of items) {
          const [, duration, easing] = item
          for (const name of [duration, easing].filter((each) => each !== undefined)) {
            const places = setAt.get(name) ?? []
            if (places.length === 0) return `${name} is set nowhere`
            const elsewhere = places.find((place) => !place.atRoot)
            if (elsewhere) return `${name} is also set by ${elsewhere.where}`
          }
          const time = rootValue(duration, 'transition-duration', ONE_TIME, 'time')
          if ('refused' in time) return time.refused
          if (easing !== undefined) {
            const curve = rootValue(easing, 'transition-timing-function', ONE_EASING, 'easing')
            if ('refused' in curve) return curve.refused
          }
          durations.push(seconds(time.value))
        }
        return durations
      }
      const plain = written(property, value, longhand)
      if (!PLAIN.test(plain)) return `not plain times for every element: ${value}`
      return plain.split(',').map(seconds)
    }

    // The selectors of a list as the engine wrote it, split at the commas outside parentheses,
    // brackets, quotes and escapes, so a selector inside `:not()` or `:is()` is never taken for
    // one of the list's own.
    const selectorsOf = (list: string): string[] => {
      const selectors: string[] = []
      let depth = 0
      let quote = ''
      let start = 0
      for (let index = 0; index < list.length; index += 1) {
        const character = list[index]
        if (character === '\\') index += 1
        else if (quote !== '') {
          if (character === quote) quote = ''
        } else if (character === '"' || character === "'") quote = character
        else if (character === '(' || character === '[') depth += 1
        else if (character === ')' || character === ']') depth -= 1
        else if (character === ',' && depth === 0) {
          selectors.push(list.slice(start, index).trim())
          start = index + 1
        }
      }
      selectors.push(list.slice(start).trim())
      return selectors
    }
    // Whether the rule's declaration of `longhand` never reaches an element. It does not when the
    // rule is a top-level one, its own declaration is not important, and every selector of the
    // rule is a selector of a top-level rule of an unconditional stylesheet that declares
    // `longhand` important. An important declaration wins over every one that is not, whatever
    // their order, specificity or layer, and the other rule applies wherever this one does; the
    // declaration that does reach the element is important, so it is read and measured on its own.
    const overridden = (rule: CSSRule, longhand: string): boolean => {
      if (namespaced || !(rule instanceof CSSStyleRule) || rule.parentRule !== null) return false
      if (rule.style.getPropertyPriority(longhand) === 'important') return false
      return selectorsOf(rule.selectorText).every((selector) =>
        unconditional.some(
          (other) =>
            other.style.getPropertyPriority(longhand) === 'important' &&
            selectorsOf(other.selectorText).includes(selector)
        )
      )
    }

    const declared = found.map(({ where, property, value, rule }) => ({
      where,
      property,
      value,
      seconds: measure(property, value),
      overridden: overridden(rule, longhandOf(property))
    }))
    return { rules, adopted: document.adoptedStyleSheets.length, declared }
  }, from)
}

/** The declarations whose durations are not all zero or 120 to 200 ms, or could not be read. */
function outsideTheRange(declared: Declared[]): Declared[] {
  return declared.filter(
    ({ seconds }) =>
      typeof seconds === 'string' ||
      seconds.some((value) => value !== 0 && !(value >= 0.12 && value <= 0.2))
  )
}

/**
 * Runs in the page. Starts recording every transition and animation that starts on the terminal's
 * surface, into a list the page keeps.
 */
function startSurfaceRecord(): void {
  const held = window as unknown as { krSurfaceMotion?: string[]; krSurfaceStop?: () => void }
  held.krSurfaceStop?.()
  const motion: string[] = []
  const started = (event: Event): void => {
    const surface = document.querySelector('[data-testid="terminal-surface"]')
    const name =
      event instanceof TransitionEvent
        ? event.propertyName
        : (event as AnimationEvent).animationName
    if (event.target instanceof Element && surface?.contains(event.target)) {
      motion.push(`${event.type} ${name} on ${event.target.getAttribute('data-testid') ?? event.target.tagName}`)
    }
  }
  document.addEventListener('transitionrun', started, true)
  document.addEventListener('animationstart', started, true)
  held.krSurfaceMotion = motion
  held.krSurfaceStop = () => {
    document.removeEventListener('transitionrun', started, true)
    document.removeEventListener('animationstart', started, true)
  }
}

/**
 * Runs in the page. Waits two frames, so what was started has been started and reported, then
 * stops the record and returns it with every animation still running on the surface.
 */
async function stopSurfaceRecord(): Promise<string[]> {
  const held = window as unknown as { krSurfaceMotion?: string[]; krSurfaceStop?: () => void }
  await new Promise<void>((resolve) => {
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        resolve()
      })
    })
  })
  const surface = document.querySelector('[data-testid="terminal-surface"]')
  const motion = [...(held.krSurfaceMotion ?? [])]
  for (const animation of document.getAnimations()) {
    const effect = animation.effect
    const target = effect instanceof KeyframeEffect ? effect.target : null
    if (target instanceof Element && surface?.contains(target)) {
      motion.push(`running ${animation.constructor.name} on ${target.getAttribute('data-testid') ?? target.tagName}`)
    }
  }
  held.krSurfaceStop?.()
  return motion
}

/** What one control does at one moment of a press, as the engine computes it. */
interface Shown {
  readonly transform: string
  /** The scale along x that the transform carries; 1 for none. */
  readonly scale: number
  /** Every running animation or transition of the element that changes its transform. */
  readonly moving: string[]
  /** How many transitions of the transform started on the element since the record began. */
  readonly runs: number
  /** The properties the element's computed `transition` names; `none` when it declares no transition. */
  readonly transition: string
}

/** Runs in the page. Records every transition of a transform that starts, by the element it starts on. */
function startTransformRecord(): void {
  const runs: EventTarget[] = []
  document.addEventListener(
    'transitionrun',
    (event) => {
      if (event.propertyName === 'transform' && event.target) runs.push(event.target)
    },
    true
  )
  ;(window as unknown as { krTransformRuns: EventTarget[] }).krTransformRuns = runs
}

/** What the control does now. */
function shown(control: Locator): Promise<Shown> {
  return control.evaluate((node) => {
    const style = getComputedStyle(node)
    const moving = node.getAnimations().flatMap((animation) => {
      const effect = animation.effect
      const names =
        effect instanceof KeyframeEffect ? effect.getKeyframes().flatMap((frame) => Object.keys(frame)) : []
      const property = 'transitionProperty' in animation ? String(animation.transitionProperty) : ''
      return property === 'transform' || names.includes('transform') ? [animation.constructor.name] : []
    })
    const record = (window as unknown as { krTransformRuns?: EventTarget[] }).krTransformRuns ?? []
    return {
      transform: style.transform,
      scale: style.transform === 'none' ? 1 : new DOMMatrix(style.transform).a,
      moving,
      runs: record.filter((target) => target === node).length,
      transition: style.transitionProperty
    }
  })
}

/** Waits two frames in the page, so that what the last input changed has been drawn and reported. */
function twoFrames(page: Page): Promise<void> {
  return page.evaluate(
    () =>
      new Promise<void>((resolve) => {
        requestAnimationFrame(() => {
          requestAnimationFrame(() => {
            resolve()
          })
        })
      })
  )
}

/**
 * A real press that is held: the pointer goes to the middle of the control and down, and stays down
 * while `during` reads the page. It is released away from the control, so that no click follows.
 */
async function held(page: Page, control: Locator, during: () => Promise<void>): Promise<void> {
  await control.scrollIntoViewIfNeeded()
  const box = await control.boundingBox()
  if (!box) throw new Error('the control has no box to press')
  await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2)
  await page.mouse.down()
  try {
    await twoFrames(page)
    await during()
  } finally {
    await page.mouse.move(1, 1)
    await page.mouse.up()
  }
}

type Rgb = readonly [number, number, number]

/**
 * The colour of the pixel 3 px below the middle of a control's top edge, as the engine drew it:
 * clear of the border, of the rounded corners and of the label, which is the control's own surface.
 * The screenshot of that one pixel is decoded in `probe`, a page of its own, so the page under test
 * is not touched.
 */
async function surfaceOf(page: Page, probe: Page, control: Locator): Promise<Rgb> {
  const box = await control.boundingBox()
  if (!box) throw new Error('the control has no box to sample')
  const png = (await page.screenshot({
    clip: { x: Math.round(box.x + box.width / 2), y: Math.round(box.y) + 3, width: 1, height: 1 }
  })) as unknown as Uint8Array
  const data = await probe.evaluate(async (bytes) => {
    const image = new Image()
    image.src = URL.createObjectURL(new Blob([new Uint8Array(bytes)], { type: 'image/png' }))
    await image.decode()
    const canvas = document.createElement('canvas')
    canvas.width = 1
    canvas.height = 1
    const context = canvas.getContext('2d')
    if (!context) throw new Error('no canvas to decode with')
    context.drawImage(image, 0, 0)
    return Array.from(context.getImageData(0, 0, 1, 1).data)
  }, Array.from(png))
  return [data[0] ?? 0, data[1] ?? 0, data[2] ?? 0]
}

/** A colour as the messages of the case print it. */
function show(colour: Rgb): string {
  return colour.join(',')
}

/** The colour of the control's label. */
async function labelOf(control: Locator): Promise<Rgb> {
  const colour = await control.evaluate((node) => getComputedStyle(node).color)
  const [r, g, b] = (colour.match(/[\d.]+/g) ?? []).map(Number)
  return [r ?? 0, g ?? 0, b ?? 0]
}

/** The WCAG contrast ratio of two colours. */
function contrast(a: Rgb, b: Rgb): number {
  const luminance = ([r, g, b]: Rgb): number => {
    const channel = (value: number): number => {
      const s = value / 255
      return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4
    }
    return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b)
  }
  const [x, y] = [luminance(a), luminance(b)]
  return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05)
}

/**
 * Whether `to` is `from` tinted toward `label`: some channel has moved by at least 6 of 255, and no
 * channel has moved away from the label, past the one step that rounding can account for.
 */
function tintedToward(from: Rgb, to: Rgb, label: Rgb): boolean {
  const moved = from.map((value, channel) => (to[channel] ?? 0) - value)
  return (
    Math.max(...moved.map(Math.abs)) >= 6 &&
    moved.every((delta, channel) => Math.abs(delta) <= 1 || delta * ((label[channel] ?? 0) - (from[channel] ?? 0)) > 0)
  )
}

/** A piece of text inside a control, with the colour the engine draws it in. */
interface Ink {
  readonly name: string
  readonly colour: Rgb
}

/**
 * Every piece of text that is drawn on the control's own surface, each in its own colour (a label, a
 * second line, a note), or the control's own colour when it holds none, as a glyph does. A text that
 * has a background of its own, such as a badge, is on that background and not on the control's.
 */
function inksOf(control: Locator): Promise<Ink[]> {
  return control.evaluate((node) => {
    const colourOf = (element: Element): [number, number, number] => {
      const [r, g, b] = (getComputedStyle(element).color.match(/[\d.]+/g) ?? []).map(Number)
      return [r ?? 0, g ?? 0, b ?? 0]
    }
    const holdsText = (element: Element): boolean =>
      [...element.childNodes].some((child) => child.nodeType === Node.TEXT_NODE && (child.textContent ?? '').trim() !== '')
    const onSurface = (element: Element): boolean => {
      const [, , , alpha] = (getComputedStyle(element).backgroundColor.match(/[\d.]+/g) ?? []).map(Number)
      return alpha === 0
    }
    const holders = [...node.querySelectorAll('*')].filter((element) => holdsText(element) && onSurface(element))
    if (holdsText(node)) holders.unshift(node)
    if (holders.length === 0) return [{ name: 'the glyph', colour: colourOf(node) }]
    return holders.map((element) => ({
      name: `"${(element.textContent ?? '').trim().slice(0, 24)}"`,
      colour: colourOf(element)
    }))
  })
}

/**
 * Holds a real press on `control` and reads what a person sees, with the pointer on it and then with
 * the pointer slid off while the press is held, as on a touch screen where nothing hovers. The engine
 * computes no transform and no transition for the pressed control; its surface is a tint of the
 * label's colour over the surface it has with the pointer on it, and over its surface at rest; every
 * text drawn on it keeps `floor` against both. `floor` is 4.5 for text and 3 for a glyph that has no
 * text. `null` is a switch's track, which has no text and keeps its colour fade.
 */
async function pressAnswers(
  page: Page,
  probe: Page,
  colorScheme: string,
  kind: string,
  control: Locator,
  floor: number | null
): Promise<void> {
  const where = `${kind}, ${colorScheme} theme`
  await control.scrollIntoViewIfNeeded()
  // At rest: the pointer is off the control, and nothing on it is still fading from an earlier change.
  await page.mouse.move(1, 1)
  await twoFrames(page)
  await expect
    .poll(() => control.evaluate((node) => node.getAnimations().length), { message: `${where}: still fading` })
    .toBe(0)
  const box = await control.boundingBox()
  if (!box) throw new Error(`${where}: no box to press`)
  const rest = await surfaceOf(page, probe, control)
  await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2)
  await twoFrames(page)
  const hovered = await surfaceOf(page, probe, control)
  await held(page, control, async () => {
    const pressed = await shown(control)
    expect(pressed.transform, `${where}: the transform of the pressed control`).toBe('none')
    expect(pressed.moving, `${where}: animations of a transform while it is pressed`).toEqual([])
    expect(pressed.runs, `${where}: transitions of a transform that started on it`).toBe(0)
    if (floor !== null) expect(pressed.transition, `${where}: the transition of the pressed control`).toBe('none')

    // With the pointer on the control, the press is a tint over the hover's surface.
    const surface = await surfaceOf(page, probe, control)
    const label = await labelOf(control)
    expect(
      tintedToward(hovered, surface, label),
      `${where}: pressed ${show(surface)} against hover ${show(hovered)}`
    ).toBe(true)
    if (floor !== null) {
      for (const ink of await inksOf(control)) {
        expect(
          contrast(ink.colour, surface),
          `${where}: ${ink.name} in ${show(ink.colour)} against the pressed surface ${show(surface)}`
        ).toBeGreaterThanOrEqual(floor)
      }
    }

    // With the pointer slid off and the press still held, it is a tint over the surface at rest, of
    // the label's colour as it is now that nothing hovers.
    await page.mouse.move(1, 1)
    await twoFrames(page)
    expect(await control.evaluate((node) => node.matches(':active')), `${where}: still pressed`).toBe(true)
    const alone = await surfaceOf(page, probe, control)
    const labelAlone = await labelOf(control)
    expect(
      tintedToward(rest, alone, labelAlone),
      `${where}: pressed ${show(alone)} against rest ${show(rest)}`
    ).toBe(true)
    if (floor !== null) {
      for (const ink of await inksOf(control)) {
        expect(
          contrast(ink.colour, alone),
          `${where}: ${ink.name} in ${show(ink.colour)} against the pressed surface ${show(alone)}, no hover`
        ).toBeGreaterThanOrEqual(floor)
      }
    }
  })
}

test.describe('motion', () => {
  // KR-REQ-13.20: every transition and animation the application's own stylesheets declare lasts 0
  // or 120 to 200 ms, as the engine reads it, including a declaration nested inside another rule; a
  // declaration two elements could read differently is refused rather than read. The same reading
  // of a sheet this test adds shows it measures what it is given, whatever else the page holds: a
  // comment inside a time, a time with no leading digit, a declaration after a nested rule, a
  // duration token a rule sets again, a variable outside the interface's tokens, a duration token
  // whose own value depends on the element, and an easing token that carries a second transition,
  // all read beside an important rule that sets every element's durations to zero.
  test('every duration the stylesheets declare is between 120 and 200 ms', async ({ page }) => {
    const sheets = ownStylesheets()
    expect(sheets.map(({ file }) => file)).toContain('styles/tokens.css')
    await page.setContent('<!doctype html><html><head></head><body></body></html>')
    for (const { text } of sheets) await page.addStyleTag({ content: text })

    const own = await motionIn(page, 0)
    expect(own.rules, 'the engine parsed the stylesheets').toBeGreaterThan(50)
    expect(own.declared.length, 'the stylesheets declare motion').toBeGreaterThan(0)
    expect(outsideTheRange(own.declared), 'a duration outside 120 to 200 ms, or unread').toEqual([])

    await page.addStyleTag({
      content: `
        * { transition-duration: 0s !important; animation-duration: 0s !important; }
        .kr-comment { transition: opacity /* duration */500ms; }
        .kr-leading { transition: transform .5s; }
        .kr-nested { @media (min-width: 0px) { color: red; } transition: opacity 500ms; }
        .kr-reset { --state: 500ms; transition: opacity var(--state) ease; }
        .kr-other { --é: 500ms; transition: opacity var(--é); }
        :root { --surface-in: calc(160ms + 340ms * sign(1em - 16px)); }
        .kr-relative { transition: opacity var(--surface-in); }
        :root { --ease-in-out: ease, opacity calc(160ms + 340ms * sign(1em - 16px)); }
        .kr-easing { transition: transform var(--press) var(--ease-in-out); }
      `
    })
    const controls = await motionIn(page, sheets.length)
    // A shorthand is read through its longhand as well, so a control can be read more than once;
    // every reading of it has to say the same thing.
    const expected: Record<string, number[] | string> = {
      '*': [0],
      '.kr-comment': [0.5],
      '.kr-leading': [0.5],
      '.kr-nested': [0.5],
      '.kr-reset': '--state is also set by .kr-reset',
      '.kr-other': 'not plain times for every element: opacity var(--é)',
      '.kr-relative':
        '--surface-in is not a plain time at the root: calc(160ms + 340ms * sign(1em - 16px))',
      '.kr-easing':
        '--ease-in-out is not a plain easing at the root: ease, opacity calc(160ms + 340ms * sign(1em - 16px))'
    }
    const readings = controls.declared.map(({ where, seconds }) => ({
      control: where.split(' ')[0],
      seconds
    }))
    expect(
      [...new Set(readings.map(({ control }) => control))],
      'every control is read'
    ).toEqual(Object.keys(expected))
    for (const { control, seconds } of readings) {
      expect(seconds, `${control} is read as what it declares`).toEqual(expected[control])
    }
  })

  // KR-REQ-13.20: in each built bundle, as its page loads it, every transition and animation its
  // stylesheets declare lasts 0 or 120 to 200 ms as the engine reads it, or never reaches an
  // element. A declaration never reaches one when every selector of its top-level rule is a
  // selector of a top-level rule, in a stylesheet that applies unconditionally, that declares the
  // same duration important, and it is not important itself; the declaration that wins instead is
  // important and is measured with the rest. The bundles carry no stylesheet of their own that the
  // application overrides. The same reading of a sheet this test adds shows what overrides: a list
  // that names the selector does, and an override that is not important, sits inside a condition or
  // inside `:not()`, or meets an important declaration, does not.
  for (const [bundle, address] of [
    ['the harness bundle', '/harness.html'],
    ['the bundle the desktop window loads', DESKTOP_BUNDLE]
  ] as const) {
    test(`every duration in ${bundle} is between 120 and 200 ms or overridden`, async ({
      page
    }) => {
      await page.goto(address)
      const read = await motionIn(page, 0)
      expect(read.adopted, 'the page adopts no stylesheet outside its document').toBe(0)
      expect(read.rules, 'the engine parsed the bundle').toBeGreaterThan(50)
      expect(read.declared.length, 'the bundle declares motion').toBeGreaterThan(0)
      expect(
        outsideTheRange(read.declared.filter(({ overridden }) => !overridden)),
        'a duration outside 120 to 200 ms that reaches an element, or unread'
      ).toEqual([])
      const overridden = read.declared
        .filter(({ overridden }) => overridden)
        .map(({ where, seconds }) => `${where}: ${JSON.stringify(seconds)}`)
      expect([...new Set(overridden)], 'what the application overrides').toEqual([])

      const before = await page.evaluate(() => document.styleSheets.length)
      await page.addStyleTag({
        content: `
          .kr-listed { transition: opacity 800ms linear; }
          .kr-else, .kr-listed { transition: none !important; }
          .kr-normal { transition: opacity 800ms linear; }
          .kr-normal { transition: none; }
          .kr-conditional { transition: opacity 800ms linear; }
          @media (min-width: 0px) { .kr-conditional { transition: none !important; } }
          .kr-negated { transition: opacity 800ms linear; }
          .kr-none:not(.kr-else, .kr-negated, .kr-other) { transition: none !important; }
          .kr-held { transition: opacity 800ms linear !important; }
          .kr-held { transition: none !important; }
        `
      })
      const controls = await motionIn(page, before)
      const reaching = outsideTheRange(controls.declared.filter(({ overridden }) => !overridden))
      expect(
        [...new Set(reaching.map(({ where }) => where))],
        'the controls whose 800 ms reaches an element'
      ).toEqual(['.kr-normal', '.kr-conditional', '.kr-negated', '.kr-held'])
      expect(
        [...new Set(controls.declared.filter(({ overridden }) => overridden).map(({ where }) => where))],
        'the one control an override reaches'
      ).toEqual(['.kr-listed'])
    })
  }

  // KR-REQ-13.20: nothing on the terminal's surface animates, with reduced motion or without. While
  // the session's screen waits and is replaced and the text is made larger and smaller, no
  // transition or animation starts anywhere on the surface. The same record sees the transition a
  // style this test adds to the surface's boxes starts, in both settings, so an empty record is a
  // measurement rather than a record that cannot see.
  test('nothing on the terminal surface animates, with reduced motion or without', async ({
    page
  }) => {
    for (const reducedMotion of ['no-preference', 'reduce'] as const) {
      await page.emulateMedia({ reducedMotion })
      await page.goto('/harness.html')
      await page.getByRole('button', { name: 'Sessions' }).click()
      await page.getByTestId('session-row-1').click()
      await page.getByRole('tab', { name: 'Terminal' }).click()
      const surface = page.getByTestId('terminal-surface')
      await expect(surface).toContainText('cargo test -p kr-client')

      await page.evaluate(startSurfaceRecord)
      await page.evaluate(() => {
        window.krTestHost?.terminalViews[0]?.wait()
        window.krTestHost?.terminalViews[0]?.show()
      })
      // A view opens in view mode, where the sizes can be pressed.
      await page.getByTestId('zoom-in').click()
      await page.getByTestId('zoom-out').click()
      await expect(surface).toContainText('cargo test -p kr-client')
      const still = await page.evaluate(stopSurfaceRecord)
      expect(still, `${reducedMotion}: motion on the terminal's surface`).toEqual([])

      await page.addStyleTag({
        content: '[data-testid="terminal-piece"] { transition: opacity 400ms linear; }'
      })
      await page.evaluate(startSurfaceRecord)
      await page.evaluate(() => {
        for (const box of Array.from(
          document.querySelectorAll<HTMLElement>('[data-testid="terminal-piece"]')
        )) {
          box.style.opacity = '0.5'
        }
      })
      const seen = await page.evaluate(stopSurfaceRecord)
      expect(
        seen.filter((entry) => entry.startsWith('transitionrun opacity')).length,
        `${reducedMotion}: the record sees a transition on the surface: ${seen.join('; ')}`
      ).toBeGreaterThan(0)
    }
  })

  // KR-REQ-13.06: with reduced motion a press keeps its feedback and loses its movement. Nine controls
  // of the four tinted classes (button, icon button, navigation item, session row) are each held down
  // by a real desktop pointer press, in the light and the dark theme, and so is a switch: the engine
  // computes no transform for the control and no transition or animation of a transform runs on it,
  // and the four classes and the switch's thumb compute no transition either; the switch's track
  // keeps its colour transitions. The press shows as a tint of the label's own colour over the control's
  // surface: the pixel sampled inside the control moves toward the label's colour from the same pixel
  // with the pointer resting on the control, and, with the pointer slid off while the press is held
  // (what a touch press has, nothing hovering, though no touch input occurs here), from the pixel at
  // rest; every text drawn on the control, read again once the pointer is off, keeps its contrast
  // against both. A switch's track takes the same tint while it is held, in both of its states and not
  // when it cannot be changed, and its thumb stands in its new place at once. Without reduced motion
  // the same press scales a button and tints nothing, so the case cannot pass on a page where nothing
  // ever scales. An engine without `color-mix` shows no tint, which is outside what a browser here
  // can run.
  test('a held press moves no control with reduced motion and tints it, and scales a button without it', async ({
    page
  }) => {
    const probe = await page.context().newPage()

    for (const colorScheme of ['light', 'dark'] as const) {
      await page.emulateMedia({ reducedMotion: 'reduce', colorScheme })
      await page.goto('/harness.html')
      await page.evaluate(startTransformRecord)

      const answers = (kind: string, control: Locator, floor: number | null): Promise<void> =>
        pressAnswers(page, probe, colorScheme, kind, control, floor)

      const sessions = page.getByRole('button', { name: 'Sessions', exact: true })
      await answers('navigation item', sessions, 4.5)
      await answers('quiet button', page.getByTestId('acknowledge').first(), 4.5)
      await answers('button', page.getByRole('button', { name: 'Open session' }).first(), 4.5)
      await sessions.click()
      await answers('current navigation item', sessions, 4.5)
      await answers('primary button', page.getByRole('button', { name: 'New session', exact: true }), 4.5)
      const row = page.getByTestId('session-row-1')
      await answers('session row', row, 4.5)
      await row.click()
      await answers('settings button', page.getByTestId('open-settings'), 4.5)
      await answers('danger button', page.getByTestId('close-session'), 4.5)
      await page.getByTestId('open-settings').click()
      await answers('icon button', page.getByRole('button', { name: 'Close settings', exact: true }), 3)

      await page.getByRole('button', { name: 'Sharing' }).click()
      const toggle = page.getByRole('switch', { name: 'Let a viewer answer questions' })
      const thumb = toggle.locator('.switch-thumb')
      await answers('switch', toggle, null)
      const before = await shown(thumb)
      await toggle.click()
      await twoFrames(page)
      const after = await shown(thumb)
      const end =
        (await toggle.getAttribute('aria-checked')) === 'true'
          ? 'matrix(1, 0, 0, 1, 14, 0)'
          : 'matrix(1, 0, 0, 1, 0, 0)'
      expect(after.transform, `the thumb two frames after the switch is pressed, ${colorScheme} theme`).toBe(end)
      expect(after.transform, 'the thumb has moved').not.toBe(before.transform)
      expect(after.moving, 'animations of the thumb').toEqual([])
      expect(after.runs, 'transitions of the thumb that started').toBe(0)
      expect(after.transition, 'the transition of the thumb').toBe('none')

      // The track takes the tint in its other state too, and a switch that cannot be changed now takes
      // none: a press that does nothing must not look like one that does.
      await answers('switch, changed', toggle, null)
      await toggle.evaluate((node) => {
        node.setAttribute('aria-disabled', 'true')
      })
      const box = await toggle.boundingBox()
      if (!box) throw new Error('the switch has no box to press')
      await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2)
      await twoFrames(page)
      const resting = await surfaceOf(page, probe, toggle)
      await held(page, toggle, async () => {
        const pressed = await surfaceOf(page, probe, toggle)
        expect(
          pressed.map((value, channel) => Math.abs(value - (resting[channel] ?? 0))).every((delta) => delta <= 1),
          `a switch that cannot be changed, ${colorScheme} theme: pressed ${show(pressed)} against resting ${show(resting)}`
        ).toBe(true)
      })
    }

    // Without reduced motion the press is the scale and nothing else: no tint.
    await page.emulateMedia({ reducedMotion: 'no-preference', colorScheme: 'light' })
    await page.goto('/harness.html')
    await page.getByRole('button', { name: 'Sessions', exact: true }).click()
    const create = page.getByRole('button', { name: 'New session', exact: true })
    await held(page, create, async () => {
      await expect
        .poll(async () => (await shown(create)).scale, { message: 'the scale of a pressed button without reduced motion' })
        .toBeCloseTo(0.97, 2)
      expect(
        await create.evaluate((node) => getComputedStyle(node).backgroundImage),
        'a pressed button without reduced motion has no tint'
      ).toBe('none')
    })
    await probe.close()
  })

  // KR-REQ-13.06: two lines that the harness does not show at rest, drawn by the product's own
  // components from made-up data, keep their contrast on the pressed surface: the second line of the
  // Account item, which shows who is signed in, and the program line under a saved command's label.
  // Both are in the faint colour, the faintest text inside a pressed control.
  test('the fainter lines inside a held control keep their contrast with reduced motion', async ({ page }) => {
    const probe = await page.context().newPage()
    for (const colorScheme of ['light', 'dark'] as const) {
      await page.emulateMedia({ reducedMotion: 'reduce', colorScheme })
      await page.goto('/harness.html')
      await page.evaluate(startTransformRecord)
      await page.evaluate(() => {
        window.krTestHost?.account.set({
          state: 'signed_in',
          email: 'sam@example.com',
          name: null,
          usage_readable: false,
          generation: 'aaaa',
          mark: 'ab'.repeat(32),
          outcome: null
        })
      })
      const account = page.getByRole('button', { name: /^Account/ })
      await expect(account.locator('.nav-item-detail')).toHaveText('sam@example.com')
      await pressAnswers(page, probe, colorScheme, 'account item', account, 4.5)

      await page.goto('/harness.html?stock_shell=bash')
      await page.waitForSelector('.app-shell')
      await page.evaluate(startTransformRecord)
      await page.evaluate(() => {
        window.krTestHost?.launchCommands.changeElsewhere([
          { label: 'Claude Code', program: '/Users/rs/.local/bin/claude', arguments: ['--resume'] },
          { label: 'Codex CLI', program: 'codex', arguments: [] }
        ])
      })
      await page.getByRole('button', { name: 'Sessions' }).click()
      await page.getByRole('button', { name: 'New session' }).click()
      const sheet = page.getByTestId('sheet')
      await expect(sheet).toHaveAttribute('data-presentation', 'here', { timeout: PRESENTATION_DEADLINE })
      await sheet.getByRole('radio', { name: /Stock shell/ }).check()
      await sheet.getByRole('textbox', { name: 'Directory' }).fill('/Users/rs/work/notes')
      await sheet.getByRole('button', { name: 'Create session' }).click()
      await expect(sheet).toBeHidden({ timeout: PRESENTATION_DEADLINE })
      await page.getByRole('button', { name: 'Dismiss' }).click()
      const saved = page.getByTestId('launch-saved').getByRole('button', { name: /Claude Code/ })
      await expect(saved.locator('.launch-program')).toHaveText('/Users/rs/.local/bin/claude')
      await pressAnswers(page, probe, colorScheme, 'saved command', saved, 4.5)
    }
    await probe.close()
  })
})
