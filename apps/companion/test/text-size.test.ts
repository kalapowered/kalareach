/**
 * The page follows the person's text size on iOS, and changes nothing anywhere else.
 *
 * KR-REQ-13.19: Dynamic Type. A test environment has no Dynamic Type, so the web view's two
 * answers are stood in for: whether it maps a font keyword to the person's text size, and what
 * size an element set in that keyword has. What is held here is what the page does with them; that
 * the real web view gives the keyword its size, and gives it a new one while the application runs,
 * is held on the iOS Simulator by `e2e/system-text-size.sh`.
 */

import { afterEach, describe, expect, it, vi } from 'vitest'

import {
  BODY_SIZE_AT_THE_DEFAULT_SETTING,
  followTheSystemTextSize,
  systemTextSizeIsAvailable,
  TEXT_SCALE
} from '../src/mobile/text-size'

/** What the web view says about the keyword, and the size it gives an element set in it. */
interface WebView {
  size: number
}

/** A resize observer that holds its callback, so a test can say the probe's box changed. */
const observers: { callback: () => void; disconnected: boolean }[] = []

/** Stands in for iOS's web view: it knows the keyword and the iOS-only property, and gives the keyword `view.size`. */
function iosWebView(view: WebView): void {
  vi.stubGlobal('CSS', {
    supports: (property: string) => property === '-webkit-touch-callout' || property === 'font'
  })
  vi.stubGlobal(
    'ResizeObserver',
    class {
      readonly entry: { callback: () => void; disconnected: boolean }
      constructor(callback: () => void) {
        this.entry = { callback, disconnected: false }
        observers.push(this.entry)
      }
      observe(): void {}
      disconnect(): void {
        this.entry.disconnected = true
      }
    }
  )
  const real = window.getComputedStyle.bind(window)
  vi.stubGlobal('getComputedStyle', (element: Element, pseudo?: string | null) => {
    const style = real(element, pseudo)
    // Only the probe is set in the keyword, and it is the one hidden element the page adds to the
    // body: every other element is the page's own.
    if (!(element instanceof HTMLElement) || element.getAttribute('aria-hidden') !== 'true') return style
    return new Proxy(style, {
      get: (target, key) => (key === 'fontSize' ? `${view.size}px` : (Reflect.get(target, key) as unknown))
    })
  })
}

const scale = (): string => document.documentElement.style.getPropertyValue(TEXT_SCALE)

afterEach(() => {
  vi.unstubAllGlobals()
  observers.length = 0
  document.documentElement.style.removeProperty(TEXT_SCALE)
  document.body.replaceChildren()
})

describe("the page follows the person's text size on iOS (KR-REQ-13.19)", () => {
  it('is 1 at the default size, so the layout every screen was drawn at is unchanged', () => {
    iosWebView({ size: BODY_SIZE_AT_THE_DEFAULT_SETTING })
    followTheSystemTextSize()
    expect(scale()).toBe('1')
  })

  it('grows by the system’s factor up to the largest accessibility size, and shrinks below the default', () => {
    for (const [points, ratio] of [
      [14, '0.8235'],
      [20, '1.1765'],
      [28, '1.6471'],
      [40, '2.3529'],
      [53, '3.1176']
    ] as const) {
      iosWebView({ size: points })
      const stop = followTheSystemTextSize()
      expect(scale(), `body text of ${points} points`).toBe(ratio)
      stop()
    }
  })

  it('takes a change made while the application runs, without a reload', () => {
    const view = { size: 17 }
    iosWebView(view)
    followTheSystemTextSize()
    expect(scale()).toBe('1')
    // The person raises the text size: the web view gives the keyword a new size and says the
    // probe's box changed.
    view.size = 53
    for (const observer of observers) observer.callback()
    expect(scale()).toBe('3.1176')
    view.size = 14
    for (const observer of observers) observer.callback()
    expect(scale()).toBe('0.8235')
  })

  it('leaves the page at the size it has when the web view answers with no size', () => {
    const view = { size: 28 }
    iosWebView(view)
    followTheSystemTextSize()
    expect(scale()).toBe('1.6471')
    for (const unusable of [Number.NaN, 0, -3]) {
      view.size = unusable
      for (const observer of observers) observer.callback()
      expect(scale(), `a size of ${unusable}`).toBe('1.6471')
    }
  })

  it('stops watching, and takes its probe and its ratio away, when told to stop', () => {
    iosWebView({ size: 40 })
    const stop = followTheSystemTextSize()
    expect(document.body.children).toHaveLength(1)
    stop()
    expect(document.body.children).toHaveLength(0)
    expect(scale()).toBe('')
    expect(observers.every((observer) => observer.disconnected)).toBe(true)
  })

  it('leaves the probe out of what a screen reader finds', () => {
    iosWebView({ size: 17 })
    followTheSystemTextSize()
    const probe = document.body.firstElementChild
    expect(probe?.getAttribute('aria-hidden')).toBe('true')
    expect(probe instanceof HTMLElement && probe.style.visibility).toBe('hidden')
  })
})

describe('a web view with no text size to follow is left alone (KR-REQ-13.19)', () => {
  it('adds nothing where the iOS-only property is missing, as on desktop Safari, which knows the keyword', () => {
    vi.stubGlobal('CSS', { supports: (property: string) => property === 'font' })
    expect(systemTextSizeIsAvailable()).toBe(false)
    followTheSystemTextSize()
    expect(document.body.children).toHaveLength(0)
    expect(scale()).toBe('')
  })

  it('adds nothing where the keyword is missing, as in Chromium', () => {
    vi.stubGlobal('CSS', { supports: (property: string) => property === '-webkit-touch-callout' })
    expect(systemTextSizeIsAvailable()).toBe(false)
    followTheSystemTextSize()
    expect(document.body.children).toHaveLength(0)
  })

  it('adds nothing where there is no CSS object at all', () => {
    vi.stubGlobal('CSS', undefined)
    expect(systemTextSizeIsAvailable()).toBe(false)
    expect(() => {
      followTheSystemTextSize()()
    }).not.toThrow()
  })
})
