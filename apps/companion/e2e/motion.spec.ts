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

import { expect, test, type Page } from '@playwright/test'

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
      await page.getByRole('tab', { name: 'View' }).click()
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
})
