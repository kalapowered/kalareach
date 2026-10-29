/**
 * The phone's session reads the output the host retained for it.
 *
 * The phone's session screen has the retained output beside the conversation and the terminal: it
 * opens at the live end, reads older pages as the reader goes up, and a change of view and back
 * returns the reader to the place they left. The output is read by the same view the desktop uses,
 * with the same method and the same bounds.
 */

import type { ReactNode } from 'react'
import { describe, expect, it } from 'vitest'
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { AppProvider } from '../../src/app/state'
import { fakeHost } from '../../src/host/fake'
import { MobileSession } from '../../src/mobile/views/MobileSession'
import { useLifecycle } from '../../src/mobile/useLifecycle'

const SESSION_MAIN = '8a7b6c50-22bb-4c3d-8e4f-000000000101'

/** The session view on its own, as the phone's shell renders it. */
function OnSession(): ReactNode {
  const lifecycle = useLifecycle(null)
  return (
    <MobileSession
      sessionId={SESSION_MAIN}
      surface="ios"
      lifecycle={lifecycle}
      connected={true}
      onBack={() => undefined}
    />
  )
}

/** The pages the output holds, by the cursor each begins at. */
const held = () =>
  [...document.querySelectorAll<HTMLElement>('[data-from]')].map((page) => page.dataset.from ?? '')

/** The scroller, placed at `top`, as a reader scrolling puts it. */
function scrollTo(top: number, height = 1000): void {
  const element = screen.getByTestId('output-scroll')
  Object.defineProperty(element, 'scrollHeight', { configurable: true, value: height })
  Object.defineProperty(element, 'clientHeight', { configurable: true, value: 200 })
  element.scrollTop = top
  fireEvent.scroll(element)
}

describe("the phone's session reads the session's retained output (KR-REQ-13.15)", () => {
  it('has an output view beside the conversation and the terminal, open at the live end', async () => {
    const person = userEvent.setup()
    const { port } = fakeHost()
    render(
      <AppProvider port={port}>
        <OnSession />
      </AppProvider>
    )
    expect(screen.getAllByRole('tab').map((tab) => tab.textContent)).toEqual([
      'Conversation',
      'Terminal',
      'Output'
    ])

    await person.click(screen.getByRole('tab', { name: 'Output' }))
    expect(await screen.findByTestId('retained-output')).toBeInTheDocument()
    await waitFor(() => {
      expect(screen.getByTestId('output-scroll').textContent).toContain('finished 900 tests')
    })
    expect(screen.getByTestId('output-scroll')).toHaveAttribute('data-following', 'true')
  })

  it('returns the reader to the page they were reading after a change of view and back', async () => {
    const person = userEvent.setup()
    const { port } = fakeHost()
    render(
      <AppProvider port={port}>
        <OnSession />
      </AppProvider>
    )
    await person.click(screen.getByRole('tab', { name: 'Output' }))
    await waitFor(() => {
      expect(held()).toHaveLength(1)
    })

    // Reading back, so that an older page is read and the reader is no longer at the live end.
    act(() => {
      scrollTo(10)
    })
    await waitFor(() => {
      expect(held().length).toBeGreaterThan(1)
    })
    const reading = held()
    expect(screen.getByTestId('output-scroll')).toHaveAttribute('data-following', 'false')

    await person.click(screen.getByRole('tab', { name: 'Conversation' }))
    expect(screen.queryByTestId('retained-output')).toBeNull()
    await person.click(screen.getByRole('tab', { name: 'Output' }))

    // The window is the one the reader left, not a new one opened at the live end.
    expect(held()).toEqual(reading)
    expect(screen.getByTestId('output-scroll')).toHaveAttribute('data-following', 'false')
  })
})
