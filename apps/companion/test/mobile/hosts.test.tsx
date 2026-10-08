/**
 * A phone pairs with a host and talks to it: the Hosts screen offers the pairing entry and the
 * hosts already paired, choosing one sends the application's commands there, and the voice entry
 * appears only while a host is being reached.
 *
 * The scripted host stands in for native code. What these hold it to is what the person sees and
 * what the page asked native code for; the paired connection itself is proved against a real host
 * in the backend's own suite.
 */

import { act, cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it } from 'vitest'

import { AppProvider } from '../../src/app/state'
import { fakeHost, type FakeHostControls } from '../../src/host/fake'
import type { HostRow } from '../../src/host/port'
import { MobileApp } from '../../src/mobile/MobileApp'

afterEach(() => {
  cleanup()
})

const STUDIO: HostRow = {
  reference: 'studio-reference',
  in_use: false,
  name: 'studio',
  owner: false,
  authority: 'view sessions',
  grant_expires_at_ms: null,
  in_contact: null
}

function start(): { controls: FakeHostControls } {
  const { port, controls } = fakeHost()
  render(
    <AppProvider port={port}>
      <MobileApp surface="ios" />
    </AppProvider>
  )
  return { controls }
}

async function openTab(name: string): Promise<void> {
  await userEvent.click(await screen.findByRole('button', { name }))
}

describe('the Hosts screen of a phone', () => {
  // KR-REQ-13.09: the pairing entry is on the Hosts screen, where a person looks for hosts.
  it('offers the pairing entry, and lists the hosts this phone is paired with', async () => {
    const { controls } = start()
    await openTab('Hosts')
    expect(await screen.findByRole('heading', { name: 'Pair with a host' })).toBeInTheDocument()
    expect(screen.queryByTestId('paired-hosts')).toBeNull()

    act(() => {
      controls.setPairing({ hosts: [STUDIO] })
    })
    const list = await screen.findByTestId('paired-hosts')
    expect(within(list).getByText('studio')).toBeInTheDocument()
    expect(list.textContent).toContain('Can view sessions')
  })

  // KR-REQ-13.08: choosing a host sends the commands there, and says which one is in use.
  it('sends the commands to the host the person chooses, and says it is in use', async () => {
    const { controls } = start()
    await openTab('Hosts')
    act(() => {
      controls.setPairing({ hosts: [STUDIO] })
    })
    await userEvent.click(await screen.findByTestId('use-host'))
    await waitFor(() => {
      expect(controls.usedHosts).toEqual(['studio-reference'])
    })
    expect(await screen.findByTestId('host-in-use')).toHaveTextContent('In use')
    expect(screen.queryByTestId('use-host')).toBeNull()
  })

  it('says why a host could not be used, and leaves the choice open', async () => {
    const { port, controls } = fakeHost()
    const refused = {
      code: 'INVALID_ARGUMENT',
      message: 'This computer is not paired with that host.',
      user_action: 'nothing'
    }
    render(
      <AppProvider port={{ ...port, hostsUse: () => Promise.reject(refused) }}>
        <MobileApp surface="ios" />
      </AppProvider>
    )
    await openTab('Hosts')
    act(() => {
      controls.setPairing({ hosts: [STUDIO] })
    })
    await userEvent.click(await screen.findByTestId('use-host'))
    expect((await screen.findByTestId('use-host-failure')).textContent).toContain(
      'not paired with that host'
    )
    expect(screen.getByTestId('use-host')).toBeEnabled()
  })
})

describe('forgetting a host on a phone', () => {
  // KR-REQ-13.08: a host this phone cannot reach any more, one that revoked it among them, stays
  // listed until the person forgets it. Forgetting asks first, because this phone cannot reach the
  // host again from here; the safe answer has the focus, and keeping the host puts it back where it
  // was.
  it('asks before it forgets a host, and forgets it once the person says so', async () => {
    const { controls } = start()
    await openTab('Hosts')
    act(() => {
      controls.setPairing({ hosts: [STUDIO] })
    })
    await userEvent.click(await screen.findByTestId('forget-host'))
    const question = await screen.findByTestId('forget-host-ask')
    expect(question).toHaveTextContent('Forget studio?')
    // What is true now: the host keeps any access it still gives this phone, and the phone does
    // not promise a way back that the host would refuse.
    expect(question).toHaveTextContent('keeps any access it still gives this phone')
    expect(question).not.toHaveTextContent('pair with it again')
    expect(question).not.toHaveTextContent('confirming requests')
    expect(screen.getByTestId('keep-host')).toHaveFocus()
    expect(controls.forgottenHosts).toEqual([])

    await userEvent.click(screen.getByTestId('keep-host'))
    expect(screen.queryByTestId('forget-host-ask')).toBeNull()
    expect(screen.getByTestId('forget-host')).toHaveFocus()
    expect(controls.forgottenHosts).toEqual([])

    await userEvent.click(screen.getByTestId('forget-host'))
    await userEvent.click(await screen.findByTestId('forget-host-confirm'))
    await waitFor(() => {
      expect(controls.forgottenHosts).toEqual(['studio-reference'])
    })
    await waitFor(() => {
      expect(screen.queryByTestId('paired-hosts')).toBeNull()
    })
    expect(screen.getByRole('heading', { name: 'Pair with a host' })).toHaveFocus()
    expect(await screen.findByText(/studio is forgotten/)).toBeInTheDocument()
  })

  // KR-REQ-13.08: the host in use that is forgotten is the host the commands stop going to.
  it('leaves the commands going nowhere when the host in use is forgotten', async () => {
    const { controls } = start()
    await openTab('Hosts')
    act(() => {
      controls.setPairing({ hosts: [{ ...STUDIO, in_use: true }] })
    })
    await userEvent.click(await screen.findByTestId('forget-host'))
    await userEvent.click(await screen.findByTestId('forget-host-confirm'))
    await waitFor(() => {
      expect(controls.forgottenHosts).toEqual(['studio-reference'])
    })
    await openTab('Sessions')
    expect(await screen.findByText('No host is being reached.')).toBeInTheDocument()
  })

  it('says why a host could not be forgotten, and leaves it listed', async () => {
    const { port, controls } = fakeHost()
    const refused = {
      code: 'RESOURCE_UNAVAILABLE',
      message: 'This computer could not change its records of hosts.',
      user_action: 'nothing'
    }
    render(
      <AppProvider port={{ ...port, hostsForget: () => Promise.reject(refused) }}>
        <MobileApp surface="ios" />
      </AppProvider>
    )
    await openTab('Hosts')
    act(() => {
      controls.setPairing({ hosts: [STUDIO] })
    })
    await userEvent.click(await screen.findByTestId('forget-host'))
    await userEvent.click(await screen.findByTestId('forget-host-confirm'))
    expect((await screen.findByTestId('forget-host-failure')).textContent).toContain(
      'could not change its records'
    )
    // The button the person pressed keeps the focus through the refusal, and can be pressed again.
    const confirm = screen.getByTestId('forget-host-confirm')
    expect(confirm).toHaveFocus()
    expect(confirm).toHaveAttribute('aria-disabled', 'false')
    expect(within(screen.getByTestId('paired-hosts')).getByText('studio')).toBeInTheDocument()
  })

  // KR-REQ-13.08: a host this phone owns says what else stops: its confirmations.
  it('says that the phone stops confirming requests when the host is one it owns', async () => {
    const { controls } = start()
    await openTab('Hosts')
    act(() => {
      controls.setPairing({ hosts: [{ ...STUDIO, owner: true }] })
    })
    await userEvent.click(await screen.findByTestId('forget-host'))
    expect(await screen.findByTestId('forget-host-ask')).toHaveTextContent(
      'This phone also stops confirming requests from it.'
    )
  })
})

describe('the lists of a phone', () => {
  // KR-REQ-13.08: what one host listed is not left on the screen once that host is not the one being
  // reached, and the lists are read again from the host that is.
  it('shows nothing of a host once it is lost, and reads the lists again when one is reached', async () => {
    const { controls } = start()
    await openTab('Sessions')
    expect(await screen.findByText('Session 1')).toBeInTheDocument()

    act(() => {
      controls.setConnected(false)
    })
    expect(await screen.findByText('No host is being reached.')).toBeInTheDocument()
    expect(screen.queryByText('Session 1')).toBeNull()

    act(() => {
      controls.setConnected(true)
    })
    expect(await screen.findByText('Session 1')).toBeInTheDocument()
  })
})

describe('the lists of a phone, when the host changes', () => {
  // KR-REQ-13.08: choosing another host while one is reached shows nothing of the first host's
  // sessions: not before the second answers, not when it answers, and not when it refuses to. A row
  // of one host is never a row that asks another.
  it('shows no session of the first host before the second answers, or when it answers or refuses', async () => {
    const { controls } = start()
    await openTab('Sessions')
    expect(await screen.findByText('Session 1')).toBeInTheDocument()

    const held = controls.hold('sessionList')
    act(() => {
      controls.switchHost('another-environment')
    })
    await waitFor(() => {
      expect(held.count).toBeGreaterThan(0)
    })
    expect(screen.queryByText('Session 1')).toBeNull()
    held.release()
    expect(await screen.findByText('No sessions on this host.')).toBeInTheDocument()
    expect(screen.queryByText('Session 1')).toBeNull()
  })

  it('shows no session of the first host when the second refuses to list its own', async () => {
    const { controls } = start()
    await openTab('Sessions')
    expect(await screen.findByText('Session 1')).toBeInTheDocument()
    act(() => {
      controls.switchHost('another-environment', { refuseSessionList: true })
    })
    expect(await screen.findByText(/may not list the sessions of this host/)).toBeInTheDocument()
    expect(screen.queryByText('Session 1')).toBeNull()
  })

  it('shows no host of the first connection before the second answers, and then the second', async () => {
    const { controls } = start()
    await openTab('Hosts')
    expect(await screen.findByText('studio · macOS')).toBeInTheDocument()

    const held = controls.hold('environmentList')
    act(() => {
      controls.switchHost('another-environment')
    })
    await waitFor(() => {
      expect(held.count).toBeGreaterThan(0)
    })
    expect(screen.queryByText('studio · macOS')).toBeNull()
    held.release()
    expect(await screen.findByText('another host · Linux')).toBeInTheDocument()
    expect(screen.queryByText('studio · macOS')).toBeNull()
  })
})

describe('the hosts list of a phone, when the second host refuses', () => {
  // KR-REQ-13.08: a host that refuses to list its own environments leaves nothing of the first.
  it('shows no host of the first connection when the second refuses to list its own', async () => {
    const { controls } = start()
    await openTab('Hosts')
    expect(await screen.findByText('studio · macOS')).toBeInTheDocument()
    act(() => {
      controls.switchHost('another-environment', { refuseEnvironmentList: true })
    })
    expect(
      await screen.findByText(/may not list the environments of this host/)
    ).toBeInTheDocument()
    expect(screen.queryByText('studio · macOS')).toBeNull()
  })
})

describe('the voice entry of a phone', () => {
  // KR-REQ-15.01: there is no one to talk to while no host is reached, so there is no entry.
  it('appears while a host is reached, and goes when it is lost', async () => {
    const { controls } = start()
    await openTab('Sessions')
    expect(await screen.findByTestId('voice-entry')).toBeInTheDocument()

    act(() => {
      controls.setConnected(false)
    })
    await waitFor(() => {
      expect(screen.queryByTestId('voice-entry')).toBeNull()
    })
    act(() => {
      controls.setConnected(true)
    })
    expect(await screen.findByTestId('voice-entry')).toBeInTheDocument()
  })

  it('opens the voice screen inside the shell, with a way back to the sessions', async () => {
    start()
    await openTab('Sessions')
    await userEvent.click(await screen.findByTestId('voice-entry'))
    expect(await screen.findByRole('button', { name: 'Start voice session' })).toBeInTheDocument()
    expect(document.querySelectorAll('main')).toHaveLength(1)
    await userEvent.click(screen.getByRole('button', { name: 'Back to sessions' }))
    expect(await screen.findByTestId('voice-entry')).toBeInTheDocument()
  })
})

describe('the pairing entry on a phone', () => {
  // KR-REQ-13.04: opening the Hosts tab raises no keyboard. The code field is there to be tapped,
  // and the screen is a place among four, not a form the person came to fill.
  it('does not take focus when the Hosts tab opens', async () => {
    start()
    await openTab('Hosts')
    const field = await screen.findByLabelText('Pairing code')
    expect(document.activeElement).not.toBe(field)
  })
})
