/**
 * The phone's shell follows the visual viewport.
 *
 * A software keyboard shrinks the visual viewport and leaves the layout viewport its height. Where
 * the platform then pans the page to keep a focused field in sight, the visual viewport is
 * scrolled down inside the layout viewport by `offsetTop`, and the top of the shell is above what
 * the person sees. The shell goes with the visual viewport by that much, and what the keyboard
 * takes is what the visual viewport lost, panned or not.
 */

import { afterEach, describe, expect, it } from 'vitest'
import { act, cleanup, render } from '@testing-library/react'

import { useKeyboardInset } from '../../src/mobile/useLifecycle'

/** A visual viewport a test moves, as a platform does. */
class FakeViewport extends EventTarget {
  height = 844
  offsetTop = 0

  move(height: number, offsetTop: number): void {
    this.height = height
    this.offsetTop = offsetTop
    this.dispatchEvent(new Event('resize'))
    this.dispatchEvent(new Event('scroll'))
  }
}

function Probe(): null {
  useKeyboardInset()
  return null
}

const root = document.documentElement
const measured = () => ({
  keyboard: root.style.getPropertyValue('--keyboard'),
  pan: root.style.getPropertyValue('--pan')
})

describe('the shell and the visual viewport', () => {
  afterEach(() => {
    cleanup()
    Reflect.deleteProperty(window, 'visualViewport')
  })

  function withViewport(): FakeViewport {
    const viewport = new FakeViewport()
    Object.defineProperty(window, 'visualViewport', { configurable: true, value: viewport })
    Object.defineProperty(window, 'innerHeight', { configurable: true, value: 844 })
    return viewport
  }

  it('says what the keyboard takes, with the page where it was', () => {
    const viewport = withViewport()
    render(<Probe />)
    expect(measured()).toEqual({ keyboard: '0px', pan: '0px' })
    act(() => {
      viewport.move(500, 0)
    })
    expect(measured()).toEqual({ keyboard: '344px', pan: '0px' })
    act(() => {
      viewport.move(844, 0)
    })
    expect(measured()).toEqual({ keyboard: '0px', pan: '0px' })
  })

  it('says what the keyboard takes and how far the page was panned, when the platform pans it for a field', () => {
    const viewport = withViewport()
    render(<Probe />)
    // The visual viewport lost the keyboard's 344 px, and the platform scrolled it all the way down
    // in the layout viewport: the bottom of the layout viewport is above the keyboard, and the top
    // 344 px of the shell are above the screen.
    act(() => {
      viewport.move(500, 344)
    })
    expect(measured()).toEqual({ keyboard: '344px', pan: '344px' })
    // Partway: the shell follows by as much as the viewport moved.
    act(() => {
      viewport.move(500, 120)
    })
    expect(measured()).toEqual({ keyboard: '344px', pan: '120px' })
  })

  it('leaves neither behind when the shell goes', () => {
    const viewport = withViewport()
    const { unmount } = render(<Probe />)
    act(() => {
      viewport.move(500, 344)
    })
    unmount()
    expect(measured()).toEqual({ keyboard: '', pan: '' })
  })
})
