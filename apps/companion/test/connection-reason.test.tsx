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
import { TopBar } from '../src/mobile/components/chrome'

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

  it('says the same when its first answer is a loss with a blank reason', async () => {
    const { port, controls } = fakeHost()
    controls.setConnected(false, '   ')
    open(port)
    await waitFor(() => {
      expect(bar()?.textContent).toBe('Not in contact')
    })
    expect(bar()?.hasAttribute('title')).toBe(false)
  })

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

/** What the line says while a try to reach the host the person chose has run for a while. */
const STILL_PAIRED = 'this application is still trying to reach the host you chose'

/** The same, for the host on this machine. */
const STILL_LOCAL = 'this application is still trying to reach the host on this machine'

/** A host's refusal, in its own words: no try is slow, so the line says them as they are. */
const REFUSED = 'the host refused the connection: PERMISSION_DENIED: this device is not paired'

describe('the desktop bar, while a slow try to reach the host is still running', () => {
  const bar = () => document.querySelector('.topbar .connection')

  function open(port: HostPort): void {
    render(
      <AppProvider port={port} initialPlace={{ view: 'plugins' }}>
        <App />
      </AppProvider>
    )
  }

  it('says the app is still trying, for each host, and the last failure again when the mark ends', async () => {
    const { port, controls } = fakeHost()
    open(port)
    await waitFor(() => {
      expect(bar()?.textContent).toBe('Connected to this machine')
    })
    act(() => {
      controls.setConnected(false, SAID)
    })
    expect(bar()?.textContent).toBe(SAID)

    act(() => {
      controls.setStillReaching('paired')
    })
    expect(bar()?.textContent).toBe(STILL_PAIRED)
    expect(bar()?.querySelector('.status-dot')?.classList.contains('offline')).toBe(true)

    act(() => {
      controls.setStillReaching('local')
    })
    expect(bar()?.textContent).toBe(STILL_LOCAL)

    act(() => {
      controls.setStillReaching(null)
    })
    expect(bar()?.textContent).toBe(SAID)
  })

  it('says it too when the failure that came before gave no reason', async () => {
    const { port, controls } = fakeHost()
    controls.setConnected(false, '  ')
    open(port)
    await waitFor(() => {
      expect(bar()?.textContent).toBe('Not in contact')
    })
    act(() => {
      controls.setStillReaching('paired')
    })
    expect(bar()?.textContent).toBe(STILL_PAIRED)
    act(() => {
      controls.setStillReaching(null)
    })
    expect(bar()?.textContent).toBe('Not in contact')
  })

  // A guard: a live connection is a connection, whatever mark a late state still carries.
  it('says it is connected while the connection is live, whatever mark the state carries', async () => {
    const { port, controls } = fakeHost()
    open(port)
    await waitFor(() => {
      expect(bar()?.textContent).toBe('Connected to this machine')
    })
    act(() => {
      controls.setStillReaching('paired')
    })
    expect(bar()?.textContent).toBe('Connected to this machine')
    expect(bar()?.querySelector('.status-dot')?.classList.contains('offline')).toBe(false)
  })

  // A guard: the host's own words after a refusal stay while no slow try is marked.
  it("shows a refusal's words, as the host said them, while no mark is set", async () => {
    const { port, controls } = fakeHost()
    open(port)
    await waitFor(() => {
      expect(bar()?.textContent).toBe('Connected to this machine')
    })
    act(() => {
      controls.setConnected(false, REFUSED)
    })
    expect(bar()?.textContent).toBe(REFUSED)
  })
})

describe("the phone's bar, while a slow try to reach the host is still running", () => {
  const bar = () => document.querySelector('.m-connection')

  function open(port: HostPort): void {
    render(
      <AppProvider port={port}>
        <MobileApp surface="ios" storage={null} />
      </AppProvider>
    )
  }

  /** The element that holds the line's words. */
  const words = () => bar()?.querySelector('span:last-child')

  // The shell copies each state before it hands it to the bar, so a field the copy leaves out
  // never reaches the line.
  it('says the app is still trying, with no title, and the last failure with its title again when the mark ends', async () => {
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

    act(() => {
      controls.setStillReaching('paired')
    })
    expect(bar()?.textContent).toBe(STILL_PAIRED)
    expect(bar()?.hasAttribute('title')).toBe(false)
    expect(bar()?.querySelector('.status-dot')?.classList.contains('offline')).toBe(true)
    // The words show whole while they stand: the two-line cut is for a reason that can run on.
    expect(words()?.classList.contains('m-connection-whole')).toBe(true)

    act(() => {
      controls.setStillReaching(null)
    })
    expect(bar()?.textContent).toBe(SAID)
    expect(bar()?.getAttribute('title')).toBe(SAID)
    expect(words()?.classList.contains('m-connection-whole')).toBe(false)
  })

  // A guard: the bar's rule is the same on the phone, and a refusal keeps its title.
  it('says it is in contact, with no title, while the connection is live whatever mark the state carries', async () => {
    const { port, controls } = fakeHost()
    open(port)
    await waitFor(() => {
      expect(bar()?.textContent).toBe('In contact with this host')
    })
    act(() => {
      controls.setStillReaching('local')
    })
    expect(bar()?.textContent).toBe('In contact with this host')
    expect(bar()?.hasAttribute('title')).toBe(false)
    expect(words()?.classList.contains('m-connection-whole')).toBe(false)
  })

  it("shows a refusal's words with the whole of them in the title while no mark is set", async () => {
    const { port, controls } = fakeHost()
    open(port)
    await waitFor(() => {
      expect(bar()?.textContent).toBe('In contact with this host')
    })
    act(() => {
      controls.setConnected(false, REFUSED)
    })
    expect(bar()?.textContent).toBe(REFUSED)
    expect(bar()?.getAttribute('title')).toBe(REFUSED)
  })
})

describe("the phone's top bar, given a connection that carries the mark", () => {
  const bar = () => document.querySelector('.m-connection')

  function show(connection: { connected: boolean; reason: string | null; reaching: 'paired' | 'local' | null } | null) {
    return render(<TopBar title="Sessions" connection={connection} surface="ios" />)
  }

  it('shows the words of each host, with no title, and the reason with its title when there is no mark', () => {
    const view = show({ connected: false, reason: SAID, reaching: 'paired' })
    expect(bar()?.textContent).toBe(STILL_PAIRED)
    expect(bar()?.hasAttribute('title')).toBe(false)
    view.unmount()

    const local = show({ connected: false, reason: SAID, reaching: 'local' })
    expect(bar()?.textContent).toBe(STILL_LOCAL)
    expect(bar()?.hasAttribute('title')).toBe(false)
    local.unmount()

    const plain = show({ connected: false, reason: SAID, reaching: null })
    expect(bar()?.textContent).toBe(SAID)
    expect(bar()?.getAttribute('title')).toBe(SAID)
    plain.unmount()

    const live = show({ connected: true, reason: null, reaching: 'paired' })
    expect(bar()?.textContent).toBe('In contact with this host')
    expect(bar()?.hasAttribute('title')).toBe(false)
    live.unmount()

    show(null)
    expect(bar()?.textContent).toBe('Checking the connection…')
    expect(bar()?.hasAttribute('title')).toBe(false)
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
