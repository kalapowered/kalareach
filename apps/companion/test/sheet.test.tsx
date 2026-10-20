/**
 * What a sheet does with the focus and with the application's own requests to close it.
 *
 * A sheet takes the focus when it opens and gives it back to the control that opened it when it
 * goes, unless something took the focus somewhere else on purpose while it was going: a request
 * that closes the sheet to show the person something else has put the focus where they can act, and
 * the sheet's leaving must not take it from there.
 */

import { act, cleanup, render, screen } from '@testing-library/react'
import type { ReactNode } from 'react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { closeSheets, Sheet } from '../src/components/ui'

const REDUCED = '(prefers-reduced-motion: reduce)'
const original = globalThis.matchMedia

beforeEach(() => {
  vi.useFakeTimers()
  // A sheet that cross-fades goes by timer, which a test can run to its end.
  vi.stubGlobal('matchMedia', (query: string) => ({
    ...original(query),
    matches: query === REDUCED
  }))
})

afterEach(() => {
  cleanup()
  vi.useRealTimers()
  vi.unstubAllGlobals()
})

function Page({ open, onClose }: { readonly open: boolean; readonly onClose: () => void }): ReactNode {
  return (
    <>
      <button type="button">Opener</button>
      <button type="button">Elsewhere</button>
      <Sheet open={open} title="A sheet" closeLabel="Close the sheet" onClose={onClose}>
        <p>The sheet’s body.</p>
      </Sheet>
    </>
  )
}

/** Lets a sheet that cross-fades finish. */
function finish(): void {
  act(() => {
    vi.advanceTimersByTime(1000)
  })
}

describe('a sheet’s focus', () => {
  it('is not modal once it is on its way out, so that what the focus went to is reachable', () => {
    const close = vi.fn()
    const { rerender } = render(<Page open onClose={close} />)
    finish()
    expect(screen.getByRole('dialog')).toHaveAttribute('aria-modal', 'true')

    rerender(<Page open={false} onClose={close} />)
    // Still drawn while it fades: a screen reader that stays inside a modal would not reach the
    // control the focus went to when it was asked to close.
    expect(screen.getByRole('dialog')).not.toHaveAttribute('aria-modal', 'true')
  })

  it('stays where something put it on purpose while the sheet was going', () => {
    const close = vi.fn()
    const { rerender } = render(<Page open={false} onClose={close} />)
    screen.getByRole('button', { name: 'Opener' }).focus()
    rerender(<Page open onClose={close} />)
    finish()

    rerender(<Page open={false} onClose={close} />)
    screen.getByRole('button', { name: 'Elsewhere' }).focus()
    finish()
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(screen.getByRole('button', { name: 'Elsewhere' })).toHaveFocus()
  })
})

describe('closing the open sheets', () => {
  it('asks each open sheet to close, as the control that closes it does, and no sheet that is not open', () => {
    const first = vi.fn()
    const second = vi.fn()
    const never = vi.fn()
    render(
      <>
        <Sheet open title="First" closeLabel="Close the first" onClose={first}>
          <p>One</p>
        </Sheet>
        <Sheet open title="Second" closeLabel="Close the second" onClose={second}>
          <p>Two</p>
        </Sheet>
        <Sheet open={false} title="Third" closeLabel="Close the third" onClose={never}>
          <p>Three</p>
        </Sheet>
      </>
    )
    act(() => {
      closeSheets()
    })
    expect(first).toHaveBeenCalledTimes(1)
    expect(second).toHaveBeenCalledTimes(1)
    expect(never).not.toHaveBeenCalled()
  })
})
