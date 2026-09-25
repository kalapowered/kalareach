/**
 * A connection lost for no stated reason, in each place that says why a connection is lost.
 *
 * Native code gives its reason in words, and the words can arrive blank: empty, or only spaces. A
 * blank reason is no reason. The page takes it in as none where it takes a connection state in, so
 * the desktop bar, the phone's bar and the setup assistant's warning each show their own words for
 * a loss with no reason given, never an empty line in their place, and show a reason with words as
 * native code sent it.
 */

import { act, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'

import { App } from '../src/App'
import { AppProvider } from '../src/app/state'
import { fakeHost } from '../src/host/fake'
import type { HostPort } from '../src/host/port'
import { MobileApp } from '../src/mobile/MobileApp'

/** Reasons that say nothing: empty, and only spaces. */
const BLANK = ['', '   '] as const

/** A reason with words, which each place shows as native code sent it. */
const SAID = 'the relay closed this connection'

describe('the desktop bar, when the connection is lost for no stated reason (KR-REQ-13.02)', () => {
  const bar = () => document.querySelector('.topbar .connection')
  const offline = () => bar()?.querySelector('.status-dot')?.classList.contains('offline')

  function open(port: HostPort): void {
    render(
      <AppProvider port={port} initialPlace={{ view: 'plugins' }}>
        <App />
      </AppProvider>
    )
  }

  for (const blank of BLANK) {
    it(`says it is not in contact, beside the offline dot, for the reason ${JSON.stringify(blank)}`, async () => {
      const { port, controls } = fakeHost()
      open(port)
      await waitFor(() => {
        expect(bar()?.textContent).toBe('Connected to this machine')
      })

      act(() => {
        controls.setConnected(false, blank)
      })
      expect(bar()?.textContent).toBe('Not in contact')
      expect(offline()).toBe(true)
    })
  }

  it('says the same when its first answer is a loss with a blank reason', async () => {
    const { port, controls } = fakeHost()
    controls.setConnected(false, '')
    open(port)
    await waitFor(() => {
      expect(bar()?.textContent).toBe('Not in contact')
    })
    expect(offline()).toBe(true)
  })

  it('shows a reason with words as native code sent it', async () => {
    const { port, controls } = fakeHost()
    open(port)
    await waitFor(() => {
      expect(bar()?.textContent).toBe('Connected to this machine')
    })

    act(() => {
      controls.setConnected(false, SAID)
    })
    expect(bar()?.textContent).toBe(SAID)
    expect(offline()).toBe(true)
  })
})

describe("the phone's bar, when the connection is lost for no stated reason (KR-REQ-13.02)", () => {
  const bar = () => document.querySelector('.m-connection')

  function open(port: HostPort): void {
    render(
      <AppProvider port={port}>
        <MobileApp surface="ios" storage={null} />
      </AppProvider>
    )
  }

  for (const blank of BLANK) {
    it(`says it is not in contact, with no title, for the reason ${JSON.stringify(blank)}`, async () => {
      const { port, controls } = fakeHost()
      open(port)
      await waitFor(() => {
        expect(bar()?.textContent).toBe('In contact with this host')
      })

      act(() => {
        controls.setConnected(false, blank)
      })
      expect(bar()?.textContent).toBe('Not in contact')
      expect(bar()?.querySelector('.status-dot')?.classList.contains('offline')).toBe(true)
      // The title keeps a long reason whole where the line is cut to two lines. Here there is no
      // reason to keep, and the words shown are short and whole.
      expect(bar()?.hasAttribute('title')).toBe(false)
    })
  }

  it('shows a reason with words as native code sent it, and keeps all of it in the title', async () => {
    const { port, controls } = fakeHost()
    open(port)
    await waitFor(() => {
      expect(bar()?.textContent).toBe('In contact with this host')
    })

    act(() => {
      controls.setConnected(false, SAID)
    })
    expect(bar()?.textContent).toBe(SAID)
    expect(bar()?.getAttribute('title')).toBe(SAID)
  })
})

describe("setup's warning, when no host answers and nothing says why (KR-REQ-13.02)", () => {
  function open(port: HostPort): void {
    render(
      <AppProvider port={port} initialPlace={{ view: 'setup' }}>
        <App />
      </AppProvider>
    )
  }

  /** What the warning says under its title, once a step past the first is open. */
  async function warning(): Promise<string> {
    await screen.findByTestId('setup-identity')
    await userEvent.click(screen.getByTestId('setup-step-permissions'))
    await screen.findByTestId('setup-panel-permissions')
    const title = await screen.findByText('No host is answering on this machine')
    return title.parentElement?.textContent ?? ''
  }

  for (const blank of BLANK) {
    it(`warns that no host is answering, and that no reason was given, for the reason ${JSON.stringify(blank)}`, async () => {
      const { port, controls } = fakeHost()
      controls.setConnected(false, blank)
      open(port)
      expect(await warning()).toMatch(
        /No reason was given\. The steps below still say what this Mac will be asked for\./
      )
    })
  }

  it('gives a reason with words as a sentence of its own', async () => {
    const { port, controls } = fakeHost()
    controls.setConnected(false, SAID)
    open(port)
    expect(await warning()).toMatch(/The relay closed this connection\. The steps below/)
  })
})
