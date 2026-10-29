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
import type { HostPort, SessionStanding } from '../../src/host/port'
import { MobileSession } from '../../src/mobile/views/MobileSession'
import { useLifecycle } from '../../src/mobile/useLifecycle'

const SESSION_MAIN = '8a7b6c50-22bb-4c3d-8e4f-000000000101'
const SHARE = '5d0e2a40-77aa-4b2c-9d3e-000000000901'

/** What the host says of an opening under a share that lets the session's output be seen. */
const OPEN_UNDER_SHARE: SessionStanding = {
  state: 'open',
  via: 'share',
  grant_id: SHARE,
  actions: ['session.view'],
  includes_live_screen: true,
  history_from_ms: null,
  ends_at_ms: null
}

/** The session view on its own, as the phone's shell renders it, under `grantId` when it names one. */
function OnSession({ grantId = null }: { readonly grantId?: string | null }): ReactNode {
  const lifecycle = useLifecycle(null)
  return (
    <MobileSession
      sessionId={SESSION_MAIN}
      grantId={grantId}
      surface="ios"
      lifecycle={lifecycle}
      connected={true}
      onBack={() => undefined}
    />
  )
}

function screenOn(port: HostPort, grantId: string | null = null): ReactNode {
  return (
    <AppProvider port={port}>
      <OnSession grantId={grantId} />
    </AppProvider>
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
    const { port, controls } = fakeHost()
    // More than a page of output, so that going back reads an older page.
    controls.records.appendOutput(
      SESSION_MAIN,
      Array.from({ length: 6000 }, (_, line) => `output line ${String(line).padStart(5, '0')}`).join('\r\n')
    )
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

describe("the phone's output is the grant the screen opened the session under (KR-REQ-13.15)", () => {
  it('asks for every page under the screen’s opening, and reads nothing before the host says it is open', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    controls.standings.answerOpens(SESSION_MAIN, {
      state: 'reconnecting',
      reason: 'Contact with the session was lost.'
    })
    render(screenOn(port, SHARE))
    await person.click(screen.getByRole('tab', { name: 'Output' }))
    expect(await screen.findByText('Not in contact with this host')).toBeInTheDocument()
    expect(controls.standings.carried.filter((call) => call.command === 'historyPage')).toEqual([])

    act(() => {
      controls.standings.say(SESSION_MAIN, OPEN_UNDER_SHARE)
    })
    await waitFor(() => {
      expect(screen.getByTestId('output-scroll').textContent).toContain('finished 900 tests')
    })
    const token = controls.standings.tokenOf(SESSION_MAIN)
    expect(token).toBeDefined()
    const pages = controls.standings.carried.filter((call) => call.command === 'historyPage')
    expect(pages.length).toBeGreaterThan(0)
    expect(pages.every((call) => call.opening === token)).toBe(true)
  })

  it('shows nothing read under the pairing once the session is opened under a share', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    const view = render(screenOn(port))
    await person.click(screen.getByRole('tab', { name: 'Output' }))
    await waitFor(() => {
      expect(held()).toHaveLength(1)
    })

    // The share's first read is held, so what the view shows meanwhile is what it kept.
    const reads = controls.hold('historyPage')
    controls.standings.answerOpens(SESSION_MAIN, OPEN_UNDER_SHARE)
    view.rerender(screenOn(port, SHARE))
    await waitFor(() => {
      expect(reads.count).toBeGreaterThan(0)
    })
    expect(held()).toEqual([])
    expect(screen.getByTestId('output-scroll').textContent).not.toContain('finished 900 tests')

    reads.release()
    await waitFor(() => {
      expect(screen.getByTestId('output-scroll').textContent).toContain('finished 900 tests')
    })
  })

  it('reads under the new opening while a read made under the old one is still on its way', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    const view = render(screenOn(port))
    await person.click(screen.getByRole('tab', { name: 'Output' }))
    await waitFor(() => {
      expect(held()).toHaveLength(1)
    })

    // The next read at the live end, made under the pairing, is on its way when the grant changes.
    const reads = controls.hold('historyPage')
    await waitFor(
      () => {
        expect(reads.count).toBe(1)
      },
      { timeout: 5000 }
    )
    controls.standings.answerOpens(SESSION_MAIN, OPEN_UNDER_SHARE)
    view.rerender(screenOn(port, SHARE))

    // The share's own first read is made without waiting for the old one to end, and what the old
    // one answers is not shown.
    await waitFor(() => {
      expect(reads.count).toBeGreaterThan(1)
    })
    reads.release()
    await waitFor(() => {
      expect(screen.getByTestId('output-scroll').textContent).toContain('finished 900 tests')
    })
    expect(held()).toHaveLength(1)
  })
})

