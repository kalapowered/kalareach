import { act, render, waitFor } from '@testing-library/react'
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
