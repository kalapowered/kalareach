/**
 * A session's retained output, read with `history.page`'s cursor and byte bound.
 *
 * The view opens at the live end, reads older pages as the reader scrolls up and newer ones as they
 * scroll back down, holds a bounded window, decodes the bytes into the text the session printed,
 * keeps up with new output only at the live end, and says what the host no longer keeps.
 */

import { describe, expect, it } from 'vitest'
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import type { HistoryPageParams } from '@kalareach/protocol'

import { App } from '../src/App'
import { AppProvider } from '../src/app/state'
import { fakeHost } from '../src/host/fake'
import type { HostPort } from '../src/host/port'
import { PAST_THE_END } from '../src/model/output'
import { RetainedOutput } from '../src/views/Output'

const SESSION_MAIN = '8a7b6c50-22bb-4c3d-8e4f-000000000101'
const SESSION_BUILD = '8a7b6c50-22bb-4c3d-8e4f-000000000102'

/** The scripted host, with every page read it is asked for recorded. */
function recording(): { port: HostPort; asked: HistoryPageParams[]; controls: ReturnType<typeof fakeHost>['controls'] } {
  const { port, controls } = fakeHost()
  const asked: HistoryPageParams[] = []
  return {
    controls,
    asked,
    port: {
      ...port,
      historyPage: (params) => {
        asked.push(params)
        return port.historyPage(params)
      }
    }
  }
}

function openOutput(port: HostPort, pageBytes = 4096, windowBytes = 12_288): void {
  render(
    <AppProvider port={port}>
      <RetainedOutput sessionId={SESSION_MAIN} pageBytes={pageBytes} windowBytes={windowBytes} />
    </AppProvider>
  )
}

/** The pages the view holds, by the cursor each begins at. */
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

describe('the retained output (KR-REQ-13.15)', () => {
  it('opens at the live end, with a cursor and a byte bound, and shows the text it printed', async () => {
    const { port, asked } = recording()
    openOutput(port)

    await waitFor(() => {
      expect(held()).toHaveLength(1)
    })
    // First where the output ends now, then the page before that end, bounded.
    expect(asked[0]).toEqual({ session_id: SESSION_MAIN, from_cursor: PAST_THE_END, max_bytes: '1' })
    const end = BigInt(asked[1]?.from_cursor ?? '0') + BigInt(asked[1]?.max_bytes ?? '0')
    expect(BigInt(asked[1]?.max_bytes ?? '0')).toBe(4096n)
    const text = screen.getByTestId('output-scroll').textContent ?? ''
    expect(text).toContain('finished 900 tests')
    // Colours and the title are what a terminal acts on, not what the session printed.
    expect(text).not.toContain('\u001b')
    expect(text).not.toContain('kalareach — zsh')
    expect(screen.getByTestId('output-scroll')).toHaveAttribute('data-following', 'true')
    expect(end).toBeGreaterThan(0n)
  })

  it('reads older pages as the reader scrolls up, and newer ones as they come back down', async () => {
    const { port, asked } = recording()
    openOutput(port)
    await waitFor(() => {
      expect(held()).toHaveLength(1)
    })
    const [last] = held()

    act(() => {
      scrollTo(10)
    })
    await waitFor(() => {
      expect(held()).toHaveLength(2)
    })
    // The page before the first, ending exactly where it begins.
    const older = asked.at(-1)
    expect(BigInt(older?.from_cursor ?? '0') + BigInt(older?.max_bytes ?? '0')).toBe(BigInt(last ?? '0'))

    // A third page fits the window; a fourth does not, and the newest page goes.
    act(() => {
      scrollTo(10)
    })
    await waitFor(() => {
      expect(held()).toHaveLength(3)
    })
    act(() => {
      scrollTo(10)
    })
    await waitFor(() => {
      expect(held()).not.toContain(last)
    })
    expect(held()).toHaveLength(3)
    expect(screen.getByTestId('output-scroll')).toHaveAttribute('data-following', 'false')

    // Back down: the page after the last is read again.
    act(() => {
      scrollTo(900)
    })
    await waitFor(() => {
      expect(held()).toContain(last)
    })
  })

  it('says what the host no longer keeps, and why, once the reader reaches it', async () => {
    const { port } = recording()
    // Pages as large as the host allows reach its oldest output in one step back.
    openOutput(port, 65_536, 524_288)
    await waitFor(() => {
      expect(held()).toHaveLength(1)
    })
    act(() => {
      scrollTo(10)
    })
    expect(await screen.findByTestId('output-gap')).toHaveTextContent(
      'Output before this is not kept: it was older than the host keeps output for.'
    )
  })

  it('keeps up with new output at the live end, and leaves a reader who scrolled away', async () => {
    const { port, controls } = recording()
    render(
      <AppProvider port={port}>
        <RetainedOutput sessionId={SESSION_MAIN} pageBytes={65_536} cadenceMs={20} />
      </AppProvider>
    )
    await waitFor(() => {
      expect(held()).toHaveLength(1)
    })
    controls.records.appendOutput(SESSION_MAIN, '\r\n$ echo written after\r\nwritten after\r\n')
    await waitFor(() => {
      expect(screen.getByTestId('output-scroll').textContent).toContain('written after')
    })

    // Scrolled away, the reader is left where they are while more is written.
    act(() => {
      scrollTo(300)
    })
    expect(screen.getByTestId('output-scroll')).toHaveAttribute('data-following', 'false')
    controls.records.appendOutput(SESSION_MAIN, 'later still\r\n')
    await act(async () => {
      await new Promise((resolve) => {
        setTimeout(resolve, 120)
      })
    })
    expect(screen.getByTestId('output-scroll').textContent).not.toContain('later still')

    // Back at the live end, it keeps up again.
    act(() => {
      scrollTo(800)
    })
    await waitFor(() => {
      expect(screen.getByTestId('output-scroll').textContent).toContain('later still')
    })
  })

  it('reads on from where an answer the host cut short ended, until the page it asked for is whole', async () => {
    const { port, asked, controls } = recording()
    // Pages that do not line up with where the host's memory begins, so reading back crosses it.
    openOutput(port, 3000, 9000)
    await waitFor(() => {
      expect(held()).toHaveLength(1)
    })
    for (const count of [2, 3]) {
      act(() => {
        scrollTo(10)
      })
      await waitFor(() => {
        expect(held()).toHaveLength(count)
      })
    }
    const end = controls.records.outputEnd(SESSION_MAIN)
    // Three whole pages back from the end, each where the one after it begins.
    expect(held()).toEqual([String(end - 9000n), String(end - 6000n), String(end - 3000n)])
    // The last of them was read in two answers: the host stopped at its memory's edge.
    const cut = asked.filter((each) => BigInt(each.from_cursor) === end - 8192n)
    expect(cut).toHaveLength(1)
    expect(screen.getByTestId('output-scroll').textContent).not.toContain('\u001b')
  })

  it('starts again where the host’s output now begins when it let go of what came after the window, and says so', async () => {
    const { port, controls } = recording()
    render(
      <AppProvider port={port}>
        <RetainedOutput sessionId={SESSION_MAIN} pageBytes={65_536} cadenceMs={20} />
      </AppProvider>
    )
    await waitFor(() => {
      expect(held()).toHaveLength(1)
    })
    // More output than the host keeps arrives before the next read: what came straight after the
    // window has gone too.
    const before = controls.records.outputEnd(SESSION_MAIN)
    controls.records.appendOutput(SESSION_MAIN, `${'x'.repeat(200)}\r\nafter the gap\r\n`)
    controls.records.forgetOutput(SESSION_MAIN, before + 100n)
    await waitFor(() => {
      expect(held()).toEqual([String(before + 100n)])
    })
    expect(screen.getByTestId('output-scroll').textContent).toContain('after the gap')
    expect(screen.getByTestId('output-gap')).toHaveTextContent(
      'Output before this is not kept: it was older than the host keeps output for.'
    )
    // And it keeps up from there.
    controls.records.appendOutput(SESSION_MAIN, 'and after that\r\n')
    await waitFor(() => {
      expect(screen.getByTestId('output-scroll').textContent).toContain('and after that')
    })
  })

  it('keeps only what it asked for when the host answers from later than asked and reads past it', async () => {
    const { port, controls } = recording()
    openOutput(port, 3000, 9000)
    await waitFor(() => {
      expect(held()).toHaveLength(1)
    })
    // The host lets output go up to partway through the page before the window's first, so it
    // answers the next read back from there, as many bytes as were asked for: past the window.
    const end = controls.records.outputEnd(SESSION_MAIN)
    controls.records.forgetOutput(SESSION_MAIN, end - 4000n)
    act(() => {
      scrollTo(10)
    })
    await waitFor(() => {
      expect(held()).toEqual([String(end - 4000n), String(end - 3000n)])
    })
    expect(screen.getByTestId('output-gap')).toHaveTextContent(
      'Output before this is not kept: it was older than the host keeps output for.'
    )
  })

  it('reads on at the live end when the host let go of everything after a reader who had scrolled back', async () => {
    const { port, controls } = recording()
    render(
      <AppProvider port={port}>
        <RetainedOutput sessionId={SESSION_MAIN} pageBytes={3000} windowBytes={6000} cadenceMs={20} />
      </AppProvider>
    )
    await waitFor(() => {
      expect(held()).toHaveLength(1)
    })
    // Back two pages: the newest page leaves the window, so the reader is no longer at the end.
    for (const count of [2, 3]) {
      act(() => {
        scrollTo(10)
      })
      await waitFor(() => {
        expect(held().length).toBeGreaterThanOrEqual(Math.min(count, 2))
      })
    }
    await waitFor(() => {
      expect(screen.getByTestId('output-scroll')).toHaveAttribute('data-following', 'false')
    })
    // Everything the host kept goes, and then the reader comes back down.
    controls.records.forgetOutput(SESSION_MAIN, controls.records.outputEnd(SESSION_MAIN))
    act(() => {
      scrollTo(900)
    })
    await waitFor(() => {
      expect(held()).toEqual([])
    })
    controls.records.appendOutput(SESSION_MAIN, 'written once it had all gone\r\n')
    await waitFor(() => {
      expect(screen.getByTestId('output-scroll').textContent).toContain('written once it had all gone')
    })
  })

  it('keeps reading at the live end of a session that had written nothing, and shows what it writes', async () => {
    const { port, controls } = fakeHost()
    render(
      <AppProvider port={port}>
        <RetainedOutput sessionId={SESSION_BUILD} cadenceMs={20} />
      </AppProvider>
    )
    expect(await screen.findByTestId('output-empty')).toBeInTheDocument()
    controls.records.appendOutput(SESSION_BUILD, '$ echo first\r\nfirst\r\n')
    await waitFor(() => {
      expect(screen.getByTestId('output-scroll').textContent).toContain('first')
    })
    expect(screen.queryByTestId('output-empty')).toBeNull()
  })

  it('says the host keeps nothing when a session wrote nothing it kept', async () => {
    const { port } = fakeHost()
    render(
      <AppProvider port={port}>
        <RetainedOutput sessionId={SESSION_BUILD} />
      </AppProvider>
    )
    expect(await screen.findByTestId('output-empty')).toHaveTextContent(
      'The host keeps nothing this session wrote.'
    )
  })

  it('says why the host would not give the output, and reads again when asked', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    controls.setConnected(false)
    render(
      <AppProvider port={port}>
        <RetainedOutput sessionId={SESSION_MAIN} />
      </AppProvider>
    )
    expect(await screen.findByText("This session's output could not be read")).toBeInTheDocument()
    act(() => {
      controls.setConnected(true)
    })
    await person.click(screen.getByRole('button', { name: 'Try again' }))
    await waitFor(() => {
      expect(held()).toHaveLength(1)
    })
    expect(screen.queryByText("This session's output could not be read")).toBeNull()
  })

  it('is one of the session views, beside the conversation and the terminal', async () => {
    const person = userEvent.setup()
    const { port } = fakeHost()
    render(
      <AppProvider
        port={port}
        initialPlace={{ view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' }}
      >
        <App />
      </AppProvider>
    )
    await person.click(await screen.findByRole('tab', { name: 'Output' }))
    expect(await screen.findByTestId('retained-output')).toBeInTheDocument()
    await waitFor(() => {
      expect(screen.getByTestId('output-scroll').textContent).toContain('finished 900 tests')
    })
  })
})
