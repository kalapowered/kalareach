/**
 * A phone turns notifications on for the host it is paired with, and a tap on one opens the
 * application on what needs the person.
 *
 * The scripted host stands in for native code: it says where notifications stand and records what
 * the page asked for. The steps native code takes (the system's permission, the notification
 * service, the challenge, the host's destination) are proved on the devices and in the backend's
 * own suite; what these hold the page to is what the person sees, the one thing they can do, and
 * that a tap on a notification lands on the attention screen.
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
  in_use: true,
  name: 'studio',
  owner: false,
  authority: 'answer questions',
  grant_expires_at_ms: null,
  in_contact: true
}

function start(): { controls: FakeHostControls } {
  const { port, controls } = fakeHost()
  controls.setPairing({ hosts: [STUDIO] })
  render(
    <AppProvider port={port}>
      <MobileApp surface="ios" />
    </AppProvider>
  )
  return { controls }
}

async function openHosts(): Promise<HTMLElement> {
  await userEvent.click(await screen.findByRole('button', { name: 'Hosts' }))
  return screen.findByTestId('host-notifications')
}

describe('the notifications of a paired host (KR-REQ-16.08)', () => {
  it('says they are off and offers the one thing the person can do', async () => {
    start()
    const row = await openHosts()
    expect(within(row).getByTestId('notifications-words').textContent).toBe('Notifications are off.')
    expect(within(row).getByRole('button', { name: 'Turn on notifications' })).toBeInTheDocument()
    expect(within(row).queryByTestId('notifications-settings')).toBeNull()
  })

  it('asks native code for the host the row belongs to, and says which step it is on', async () => {
    const person = userEvent.setup()
    const { controls } = start()
    const row = await openHosts()
    await person.click(within(row).getByRole('button', { name: 'Turn on notifications' }))
    await waitFor(() => {
      expect(controls.pushEnabled).toEqual(['studio-reference'])
    })
    const words = await within(row).findByText('Asking for permission.')
    // A step in progress is a status, said politely. Nothing is wrong, so it is not an alert.
    expect(words).toHaveAttribute('role', 'status')
    expect(within(row).queryByRole('button', { name: 'Turn on notifications' })).toBeNull()
    expect(within(row).queryByRole('alert')).toBeNull()
  })

  it('follows what native code publishes, and offers nothing once they are on', async () => {
    const { controls } = start()
    const row = await openHosts()
    act(() => {
      controls.setPush({
        available: true,
        hosts: [{ reference: 'studio-reference', state: 'on', words: '', settings: false }]
      })
    })
    await waitFor(() => {
      expect(within(row).getByTestId('notifications-words').textContent).toBe('Notifications are on.')
    })
    expect(within(row).queryByRole('button')).toBeNull()
  })

  // The system's setting is the person's alone: the page says so in words and links to it.
  it('names what the person has to change in the system and links to its settings', async () => {
    const person = userEvent.setup()
    const { controls } = start()
    const row = await openHosts()
    act(() => {
      controls.setPush({
        available: true,
        hosts: [
          {
            reference: 'studio-reference',
            state: 'needs_attention',
            words: 'Notifications are turned off for KalaReach in Settings.',
            settings: true
          }
        ]
      })
    })
    const words = await within(row).findByText(
      'Notifications are turned off for KalaReach in Settings.'
    )
    expect(words).not.toHaveAttribute('role', 'status')
    expect(within(row).getByRole('button', { name: 'Try again' })).toBeInTheDocument()
    expect(controls.settingsOpened.count).toBe(0)
    await person.click(within(row).getByRole('button', { name: 'Open settings' }))
    expect(controls.settingsOpened.count).toBe(1)
  })

  it('offers the system settings only where the system is what stopped it', async () => {
    const { controls } = start()
    const row = await openHosts()
    act(() => {
      controls.setPush({
        available: true,
        hosts: [
          {
            reference: 'studio-reference',
            state: 'needs_attention',
            words: 'The host did not answer. Try again when it is reachable.',
            settings: false
          }
        ]
      })
    })
    await within(row).findByText('The host did not answer. Try again when it is reachable.')
    expect(within(row).getByRole('button', { name: 'Try again' })).toBeInTheDocument()
    expect(within(row).queryByRole('button', { name: 'Open settings' })).toBeNull()
  })

  it('looks again each time the application comes to the front', async () => {
    const { controls } = start()
    const row = await openHosts()
    const before = controls.pushLooks.count
    // A person who left to change the system's setting comes back to the screen they left.
    act(() => {
      document.dispatchEvent(new Event('visibilitychange'))
    })
    await waitFor(() => {
      expect(controls.pushLooks.count).toBeGreaterThan(before)
    })
    expect(row).toBeInTheDocument()
  })

  it('shows nothing of notifications on a device that has none', async () => {
    const { port, controls } = fakeHost()
    controls.setPairing({ hosts: [STUDIO] })
    controls.setPush({ available: false, hosts: [] })
    render(
      <AppProvider port={port}>
        <MobileApp surface="ios" />
      </AppProvider>
    )
    await userEvent.click(await screen.findByRole('button', { name: 'Hosts' }))
    await screen.findByTestId('paired-hosts')
    expect(screen.queryByTestId('host-notifications')).toBeNull()
  })
})

describe('a tap on a notification (KR-REQ-09.21)', () => {
  const current = (): string =>
    screen.getAllByRole('button').find((each) => each.getAttribute('aria-current') === 'page')
      ?.textContent ?? ''
  const comesToTheFront = (): void => {
    act(() => {
      document.dispatchEvent(new Event('visibilitychange'))
    })
  }
  const onHosts = async (): Promise<FakeHostControls> => {
    const { port, controls } = fakeHost()
    render(
      <AppProvider port={port}>
        <MobileApp surface="ios" />
      </AppProvider>
    )
    await userEvent.click(await screen.findByRole('button', { name: 'Hosts' }))
    await waitFor(() => {
      expect(current()).toContain('Hosts')
    })
    return controls
  }

  // The person left the application on the Hosts screen. The notification said something needs
  // them, and what needs them is on the attention screen, so that is where the tap leaves them.
  it('opens the application on the attention screen, where what needs the person is', async () => {
    const controls = await onHosts()
    controls.routeNextTapTo('attention')
    comesToTheFront()
    await waitFor(() => {
      expect(current()).toContain('Attention')
    })
  })

  it('leaves the person where they are when nothing opened the application', async () => {
    const controls = await onHosts()
    const asked = controls.routeAsks.count
    comesToTheFront()
    // The page asked again, was told of no tap, and the person is where they were.
    await waitFor(() => {
      expect(controls.routeAsks.count).toBeGreaterThan(asked)
    })
    expect(current()).toContain('Hosts')
  })

  it('goes there once: a later look finds no tap to follow', async () => {
    const person = userEvent.setup()
    const controls = await onHosts()
    controls.routeNextTapTo('attention')
    comesToTheFront()
    await waitFor(() => {
      expect(current()).toContain('Attention')
    })
    await person.click(await screen.findByRole('button', { name: 'Hosts' }))
    const asked = controls.routeAsks.count
    comesToTheFront()
    await waitFor(() => {
      expect(controls.routeAsks.count).toBeGreaterThan(asked)
    })
    expect(current()).toContain('Hosts')
  })
})
