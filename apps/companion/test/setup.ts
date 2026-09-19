/**
 * What a component test needs that jsdom does not provide.
 *
 * Only the browser features the interface genuinely uses are filled in, and each is the simplest
 * thing that behaves like the real one. A stub that behaved differently would make a test pass for
 * a reason the application does not have.
 */

import '@testing-library/jest-dom/vitest'
import { cleanup } from '@testing-library/react'
import { afterEach } from 'vitest'

// The testing library tidies up after itself only when it can see a global `afterEach`, and this
// project does not put the test globals on `globalThis`.
afterEach(cleanup)

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
