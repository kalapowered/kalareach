/**
 * What a component test needs that jsdom does not provide.
 *
 * Only the browser features the interface genuinely uses are filled in, and each is the simplest
 * thing that behaves like the real one. A stub that behaved differently would make a test pass for
 * a reason the application does not have.
 */

import '@testing-library/jest-dom/vitest'
import { cleanup, configure } from '@testing-library/react'
import { afterEach, vi } from 'vitest'

// The testing library tidies up after itself only when it can see a global `afterEach`, and this
// project does not put the test globals on `globalThis`.
afterEach(cleanup)

// How long a wait is given before the run is called hung.
//
// Neither of these is an estimate of how long the interface takes, and nothing in these tests waits
// for a length of time: every wait below is a condition, and it costs what it always did when it is
// met. They are here because some of what is waited for is motion. A sheet arrives and leaves one
// animation frame at a time, and a frame advances it by at most a frame's worth of its own time, so
// what it costs is frames rather than seconds and how long a frame lasts is the machine's answer
// rather than this application's: the flick that dismisses one spends
// three quarters of the library's own one-second default on an idle machine, and a machine running
// several builds at once would lose to it while nothing at all was wrong. These two are the chosen
// liveness limits: a machine can always be slow enough to pass any fixed figure, so they are the
// point past which waiting longer is worth less than being told what the wait was for.
configure({ asyncUtilTimeout: 20_000 })
vi.setConfig({ testTimeout: 30_000 })

// jsdom has no layout, so an element's height is zero and the sheet's own measurements would be
// meaningless. A fixed height makes the drag arithmetic testable.
Object.defineProperty(HTMLElement.prototype, 'offsetHeight', {
  configurable: true,
  get() {
    return 400
  }
})

if (!('PointerEvent' in globalThis)) {
  // jsdom ships MouseEvent but not PointerEvent. The interface listens for pointer events because
  // they are the ones that carry a pointer identity, so the tests need the same shape.
  class TestPointerEvent extends MouseEvent {
    readonly pointerId: number
    readonly pointerType: string

    constructor(type: string, init: PointerEventInit = {}) {
      super(type, init)
      this.pointerId = init.pointerId ?? 1
      this.pointerType = init.pointerType ?? 'mouse'
    }
  }
  Object.defineProperty(globalThis, 'PointerEvent', {
    configurable: true,
    value: TestPointerEvent
  })
}

if (!HTMLElement.prototype.setPointerCapture) {
  HTMLElement.prototype.setPointerCapture = () => undefined
  HTMLElement.prototype.releasePointerCapture = () => undefined
  HTMLElement.prototype.hasPointerCapture = () => false
}

if (typeof globalThis.matchMedia !== 'function') {
  Object.defineProperty(globalThis, 'matchMedia', {
    configurable: true,
    value: (query: string) => ({
      matches: false,
      media: query,
      onchange: null,
      addEventListener: () => undefined,
      removeEventListener: () => undefined,
      addListener: () => undefined,
      removeListener: () => undefined,
      dispatchEvent: () => false
    })
  })
}

if (!('createObjectURL' in URL)) {
  Object.defineProperty(URL, 'createObjectURL', {
    configurable: true,
    value: () => 'blob:test'
  })
}
