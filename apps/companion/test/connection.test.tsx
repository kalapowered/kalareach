import { act, render, waitFor, within } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import { App } from '../src/App'
import { AppProvider } from '../src/app/state'
import { fakeHost } from '../src/host/fake'

/** What the connection indicator in the top bar says. */
function indicator(container: HTMLElement): string | null | undefined {
  return container.querySelector('.topbar .connection')?.textContent
}

const UNREACHABLE = 'this host cannot be contacted right now'

function shell() {
  const { port, controls } = fakeHost()
  return { port, controls }
}

describe('the connection indicator', () => {
  it('follows the connection, with the reason native code gives', async () => {
    const { port, controls } = shell()
    const { container } = render(
      <AppProvider port={port} initialPlace={{ view: 'plugins' }}>
        <App />
      </AppProvider>
    )
    await waitFor(() => {
      expect(indicator(container)).toBe('Connected to this machine')
    })
    act(() => {
      controls.setConnected(false)
    })
    expect(indicator(container)).toBe(UNREACHABLE)
    act(() => {
      controls.setConnected(true)
    })
    expect(indicator(container)).toBe('Connected to this machine')
  })

  it('reads the state once it is listening, so a change while it registers is shown', async () => {
    const { port, controls } = shell()
    const complete = controls.holdRegistrations()
    const { container } = render(
      <AppProvider port={port} initialPlace={{ view: 'plugins' }}>
        <App />
      </AppProvider>
    )
    act(() => {
      controls.setConnected(false)
    })
    await act(async () => {
      complete()
      await Promise.resolve()
    })
    await waitFor(() => {
      expect(indicator(container)).toBe(UNREACHABLE)
    })
  })

  it('keeps a change it heard over a state it read before the change', async () => {
    const { port, controls } = shell()
    const held = controls.hold('connectionState')
    const { container } = render(
      <AppProvider port={port} initialPlace={{ view: 'plugins' }}>
        <App />
      </AppProvider>
    )
    // The listener is registered, and the state it read is still on its way.
    await act(async () => {
      await Promise.resolve()
    })
    act(() => {
      controls.setConnected(false)
    })
    await act(async () => {
      held.release()
      await Promise.resolve()
    })
    expect(indicator(container)).toBe(UNREACHABLE)
  })
})

describe('nothing is claimed about the connection before a first answer (KR-REQ-13.02)', () => {
  /** The indicator's status dot, if it has one. */
  function dot(container: HTMLElement): Element | null {
    return container.querySelector('.topbar .connection .status-dot')
  }

  it('says it is checking, with no dot, until its first read answers, and then what it read', async () => {
    const { port, controls } = shell()
    const held = controls.hold('connectionState')
    const { container } = render(
      <AppProvider port={port} initialPlace={{ view: 'plugins' }}>
        <App />
      </AppProvider>
    )
    await waitFor(() => {
      expect(held.count).toBe(1)
    })
    expect(indicator(container)).toBe('Checking the connection…')
    expect(dot(container)).toBeNull()

    await act(async () => {
      held.release()
      await new Promise((resolve) => {
        setTimeout(resolve, 0)
      })
    })
    expect(indicator(container)).toBe('Connected to this machine')
    expect(dot(container)?.classList.contains('offline')).toBe(false)
  })

  it('shows a first read that failed as a failure, in its own words', async () => {
    const { port } = shell()
    const { container } = render(
      <AppProvider
        port={{
          ...port,
          connectionState: () =>
            Promise.reject({
              code: 'INTERNAL',
              message: 'The backend did not answer.',
              user_action: 'retry'
            })
        }}
        initialPlace={{ view: 'plugins' }}
      >
        <App />
      </AppProvider>
    )
    await waitFor(() => {
      expect(indicator(container)).toBe('The backend did not answer.')
    })
    expect(dot(container)?.classList.contains('offline')).toBe(true)
  })

  it('the hosts screen claims no contact before its first answer, then shows it', async () => {
    const { port, controls } = shell()
    const info = controls.hold('hostInfo')
    render(
      <AppProvider port={port} initialPlace={{ view: 'hosts' }}>
        <App />
      </AppProvider>
    )
    await waitFor(() => {
      expect(info.count).toBe(1)
    })
    // The card for this machine: its name, whether it is in contact, and its environments.
    const card = () => document.querySelector<HTMLElement>('main .card') ?? document.body
    expect(within(card()).queryAllByText(/Connected|Disconnected|Not in contact/)).toEqual([])
    expect(within(card()).getByText('Reading this host…')).toBeInTheDocument()

    await act(async () => {
      info.release()
      await new Promise((resolve) => {
        setTimeout(resolve, 0)
      })
    })
    expect(within(card()).getAllByText(/Connected/).length).toBeGreaterThan(0)
  })

  it('shows the connection it read when nothing was held', async () => {
    const { port } = shell()
    const { container } = render(
      <AppProvider port={port} initialPlace={{ view: 'plugins' }}>
        <App />
      </AppProvider>
    )
    await waitFor(() => {
      expect(indicator(container)).toBe('Connected to this machine')
    })
  })
})
