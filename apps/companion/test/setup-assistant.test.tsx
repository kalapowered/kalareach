/**
 * The setup assistant, driven the way a person drives it.
 *
 * The screen under test is the one the desktop shell loads, and the answers come from the scripted
 * host, so what is exercised here is the real path from a protocol record to what somebody is
 * told about their own machine.
 *
 * Two of these are not about a screen at all. One counts every operation the assistant performs
 * from first paint to the last step, because the product's promise is that nothing in setup needs
 * an account and the way to keep that promise is to know exactly what setup calls. The other
 * checks that a capability nobody has established is never shown as one that works.
 */

import { describe, expect, it } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { App } from '../src/App'
import { AppProvider } from '../src/app/state'
import { fakeHost, type FakeHostControls } from '../src/host/fake'
import type { HostPort } from '../src/host/port'
import { DEFAULT_MODEL, readableBytes } from '../src/setup/host'

/** Every operation the interface performed, in order. */
function watched(port: HostPort): { port: HostPort; calls: string[] } {
  const calls: string[] = []
  const seen = new Proxy(port, {
    get(target, name: string) {
      const value: unknown = Reflect.get(target, name) as unknown
      if (typeof value !== 'function') return value
      const operation = value as (this: HostPort, ...rest: unknown[]) => unknown
      // Bound to the port, so the operation runs exactly as the interface would have run it.
      return (...args: unknown[]) => {
        calls.push(name)
        return Reflect.apply(operation, target, args)
      }
    }
  })
  return { port: seen, calls }
}

function start(): { controls: FakeHostControls; calls: string[] } {
  const host = fakeHost()
  const { port, calls } = watched(host.port)
  render(
    <AppProvider port={port} initialPlace={{ view: 'setup' }}>
      <App />
    </AppProvider>
  )
  return { controls: host.controls, calls }
}

async function goTo(step: string): Promise<void> {
  await userEvent.click(screen.getByTestId(`setup-step-${step}`))
  await screen.findByTestId(`setup-panel-${step}`)
}

describe('the identity setup checks before anything else', () => {
  it('names the application a grant would be filed under, and the host beside it', async () => {
    start()
    const identity = await screen.findByTestId('setup-identity')
    expect(within(identity).getByText('to.kala.companion')).toBeInTheDocument()
    expect(within(identity).getByText('Stable identity')).toBeInTheDocument()
    expect(screen.getByTestId('setup-helper').textContent).toMatch(/kr-controller/)
  })

  it('says outright that a build whose identity moves loses every grant', async () => {
    const { controls } = start()
    await screen.findByTestId('setup-identity')
    controls.setIdentityStable(false)
    await goTo('capabilities')
    await userEvent.click(screen.getByTestId('setup-recheck'))
    await goTo('identity')
    await waitFor(() => {
      expect(screen.getByTestId('setup-identity').textContent).toMatch(
        /Identity moves between launches/
      )
    })
    expect(screen.getByTestId('setup-identity').textContent).toMatch(
      /Install a signed build before granting anything/
    )
    expect(screen.getByTestId('setup-signature').textContent).toMatch(/ad-hoc signature/)
  })

  it('states what no check can establish, wherever the identity is shown', async () => {
    start()
    const ceiling = await screen.findByTestId('setup-ceiling-identity')
    expect(ceiling.textContent).toMatch(/cannot tell you a permission has been granted/)
    expect(ceiling.textContent).toMatch(/perform the operation the permission guards/)
    // And the signature itself is named, because that is what a grant is filed against.
    expect(screen.getByTestId('setup-signature').textContent).toMatch(/Developer ID Application/)
  })
})

describe('the permission categories', () => {
  it('guides each one on its own, with the route the person has to take', async () => {
    start()
    await screen.findByTestId('setup-identity')
    await goTo('permissions')
    for (const pane of ['accessibility', 'screen_recording', 'full_disk_access', 'automation']) {
      const route = screen.getByTestId(`setup-route-${pane}`)
      expect(route.textContent).toMatch(/System Settings/)
      expect(route.textContent).toMatch(/this switch cannot be set from here/)
      expect(screen.getByTestId(`setup-open-${pane}`)).toBeInTheDocument()
    }
  })

  it('says Full Disk Access does not stand in for the others', async () => {
    start()
    await screen.findByTestId('setup-identity')
    await goTo('permissions')
    expect(screen.getByTestId('setup-caveat-full_disk_access').textContent).toMatch(
      /still cannot take a screen image or send a keystroke/
    )
  })

  it('shows the microphone and remote desktop only for the features that use them', async () => {
    start()
    await screen.findByTestId('setup-identity')
    await goTo('permissions')
    expect(screen.getByTestId('setup-permission-microphone').textContent).toMatch(/for voice/)
    expect(screen.getByTestId('setup-permission-remote_desktop').textContent).toMatch(
      /for reaching this desktop from elsewhere/
    )
  })

  it('opens the pane the person asked for and nothing else', async () => {
    const { controls } = start()
    await screen.findByTestId('setup-identity')
    await goTo('permissions')
    await userEvent.click(screen.getByTestId('setup-open-screen_recording'))
    await waitFor(() => {
      expect(controls.openedPanes).toEqual(['screen_recording'])
    })
  })

  it('asks for a restart once a grant was given and the answer did not move', async () => {
    const { controls } = start()
    await screen.findByTestId('setup-identity')
    await goTo('permissions')
    await userEvent.click(screen.getByTestId('setup-open-screen_recording'))
    await waitFor(() => {
      expect(controls.openedPanes.length).toBe(1)
    })
    await goTo('capabilities')
    await userEvent.click(screen.getByTestId('setup-recheck'))
    await waitFor(() => {
      expect(screen.getByTestId('setup-state-desktop.screen_capture').textContent).toBe(
        'Restart required'
      )
    })
  })

  it('reports ready once the operation itself works', async () => {
    const { controls } = start()
    await screen.findByTestId('setup-identity')
    await goTo('capabilities')
    expect(screen.getByTestId('setup-state-desktop.screen_capture').textContent).toBe(
      'Permission required'
    )
    controls.grantPermission('desktop.screen_capture')
    await userEvent.click(screen.getByTestId('setup-recheck'))
    await waitFor(() => {
      expect(screen.getByTestId('setup-state-desktop.screen_capture').textContent).toBe('Ready')
    })
  })
})

describe('what the machine can do, and how that is known', () => {
  it('keeps a tool-specific permission its own record rather than a global success', async () => {
    const { controls } = start()
    await screen.findByTestId('setup-identity')
    await goTo('capabilities')
    controls.grantPermission('desktop.accessibility')
    await userEvent.click(screen.getByTestId('setup-recheck'))
    await waitFor(() => {
      expect(screen.getByTestId('setup-state-desktop.accessibility').textContent).toBe('Ready')
    })
    expect(screen.getByTestId('setup-state-desktop.screen_capture').textContent).toBe(
      'Permission required'
    )
    expect(screen.getByTestId('setup-state-desktop.input_injection').textContent).toBe('Not checked')
  })

  it('shows a check nobody has run as a first-class answer rather than a failure', async () => {
    start()
    await screen.findByTestId('setup-identity')
    await goTo('capabilities')
    const card = screen.getByTestId('setup-capability-desktop.input_injection')
    expect(within(card).getByText('Not checked')).toBeInTheDocument()
    expect(card.textContent).toMatch(/nothing is known about it either way/i)
    expect(card.textContent).not.toMatch(/failed|broken|error/i)
  })

  it('says what produced each answer and what would make it stale', async () => {
    start()
    await screen.findByTestId('setup-identity')
    await goTo('capabilities')
    await userEvent.click(screen.getByTestId('setup-evidence-toggle-desktop.screen_capture'))
    const card = screen.getByTestId('setup-capability-desktop.screen_capture')
    expect(card.textContent).toMatch(/a check run in this execution context/)
    expect(card.textContent).toMatch(/\/usr\/sbin\/screencapture/)
    expect(card.textContent).toMatch(/desktop_bound/)
    expect(card.textContent).toMatch(/the tool is replaced/)
    expect(card.textContent).toMatch(/a permission changes/)
    expect(card.textContent).toMatch(/you log in again/)
  })

  it('declares what each check does before any of them is asked for', async () => {
    start()
    await screen.findByTestId('setup-identity')
    await goTo('capabilities')
    const [explain] = screen.getAllByRole('button', { name: 'What the checks do' })
    if (!explain) throw new Error('the assistant offers to explain the checks')
    await userEvent.click(explain)
    const effects = await screen.findByTestId('setup-effects')
    expect(effects.textContent).toMatch(/removes it before answering/)
    expect(effects.textContent).toMatch(/Selects nothing, moves nothing, clicks nothing/)
    expect(effects.textContent).toMatch(/only inside a test context of its own/)
    expect(screen.getByTestId('sheet').textContent).toMatch(
      /None of them sends input to an application you did not ask about/
    )
  })

  it('never says the count is complete while something is unchecked', async () => {
    start()
    await screen.findByTestId('setup-identity')
    const tally = await screen.findByTestId('setup-tally')
    await waitFor(() => {
      expect(tally.textContent).toMatch(/3 of 6 established/)
    })
    expect(tally.textContent).toMatch(/2 waiting on you/)
    expect(tally.textContent).toMatch(/1 not checked/)
  })
})

describe('how KalaReach runs here', () => {
  it('offers the graphical host, the headless host and a terminal profile separately', async () => {
    start()
    await screen.findByTestId('setup-identity')
    await goTo('host')
    for (const id of ['gui_host', 'headless_host', 'terminal_profile']) {
      const card = screen.getByTestId(`setup-install-${id}`)
      expect(within(card).getByRole('switch')).toHaveAttribute('aria-checked', 'false')
    }
  })

  it('says what a logout does to each profile', async () => {
    start()
    await screen.findByTestId('setup-identity')
    await goTo('host')
    expect(screen.getByTestId('setup-persistence-gui_host').textContent).toMatch(
      /Ends when you log out/
    )
    expect(screen.getByTestId('setup-persistence-headless_host').textContent).toMatch(
      /not established here/
    )
  })

  it('offers the sleep setting and leaves it off', async () => {
    start()
    await screen.findByTestId('setup-identity')
    await goTo('host')
    const sleep = screen.getByTestId('setup-sleep')
    expect(screen.getByTestId('setup-sleep-now').textContent).toMatch(/It is off\./)
    expect(screen.getByTestId('setup-sleep-off').textContent).toMatch(/set now/)
    expect(sleep.textContent).toMatch(/Setting up KalaReach does not change it/)
    expect(screen.getByTestId('setup-sleep-mains_only').textContent).toMatch(
      /kr host power --set mains_only/
    )
    expect(screen.getByTestId('setup-sleep-battery_too').textContent).toMatch(
      /separate choice from the one above/
    )
    expect(within(sleep).queryByRole('switch')).toBeNull()
  })

  it('states the download size and lets it be cancelled and turned off', async () => {
    start()
    await screen.findByTestId('setup-identity')
    await goTo('host')
    expect(screen.getByTestId('setup-model-size').textContent).toBe(
      `${readableBytes(DEFAULT_MODEL.bytes)} to download.`
    )
    await userEvent.click(screen.getByTestId('setup-model-download'))
    expect(screen.getByTestId('setup-model').textContent).toMatch(/Chosen/)
    await userEvent.click(screen.getByTestId('setup-model-cancel'))
    expect(screen.getByTestId('setup-model').textContent).toMatch(/Cancelled/)
    await userEvent.click(screen.getByTestId('setup-model-decline'))
    expect(screen.getByTestId('setup-model').textContent).toMatch(/Turned off/)
  })

  it('finishes with the download declined and nothing installed', async () => {
    start()
    await screen.findByTestId('setup-identity')
    await goTo('host')
    await userEvent.click(screen.getByTestId('setup-model-decline'))
    await goTo('ready')
    expect(screen.getByTestId('setup-nothing-chosen').textContent).toMatch(
      /KalaReach works from here without any of it/
    )
    expect(screen.getByTestId('setup-chosen').textContent).toMatch(/Turned off/)
  })
})

describe('what setup costs a person', () => {
  it('asks for no account and says so', async () => {
    start()
    await screen.findByTestId('setup-identity')
    await goTo('ready')
    const said = screen.getByTestId('setup-panel-ready').textContent ?? ''
    expect(said).toMatch(/no Cloudflare, Stripe, Firebase or Apple developer account/)
    expect(said).toMatch(/nothing on this screen signed you up for anything/)
  })

  it('performs only three host operations from first paint to the last step', async () => {
    const { calls } = start()
    await screen.findByTestId('setup-identity')
    for (const step of ['permissions', 'capabilities', 'host', 'ready']) {
      await goTo(step)
    }
    await userEvent.click(screen.getByTestId('setup-step-capabilities'))
    await screen.findByTestId('setup-panel-capabilities')
    await userEvent.click(screen.getByTestId('setup-recheck'))
    await waitFor(() => {
      expect(screen.getByTestId('setup-recheck').textContent).toBe('Check again')
    })

    // The shell's own connection watch and event subscription are the application's, not setup's,
    // and so is its read of the account the sidebar names, which reaches no host.
    const own = calls.filter(
      (name) => !['connectionState', 'subscribe', 'accountStatus', 'onAccount'].includes(name)
    )
    expect(new Set(own)).toEqual(
      new Set(['setupIdentity', 'environmentCapabilities'])
    )
    // Nothing on this path signs in, pairs, pays or registers for anything. The shell's read of
    // where the account stands, and its subscription to changes, sign nothing in.
    for (const name of calls.filter((name) => !['accountStatus', 'onAccount'].includes(name))) {
      expect(name).not.toMatch(/account|sign|billing|stripe|firebase|apple/i)
    }
  })

  it('opens a settings pane only when the person presses the control for it', async () => {
    const { calls, controls } = start()
    await screen.findByTestId('setup-identity')
    await goTo('permissions')
    expect(calls).not.toContain('openSettingsPane')
    expect(controls.openedPanes).toEqual([])
    await userEvent.click(screen.getByTestId('setup-open-accessibility'))
    await waitFor(() => {
      expect(controls.openedPanes).toEqual(['accessibility'])
    })
  })
})

describe('when there is no host on this machine', () => {
  it('still says what this Mac will be asked for, in whole sentences', async () => {
    const host = fakeHost()
    host.controls.setConnected(false)
    const { port } = watched(host.port)
    render(
      <AppProvider port={port} initialPlace={{ view: 'setup' }}>
        <App />
      </AppProvider>
    )
    await screen.findByTestId('setup-identity')
    await goTo('permissions')
    const banner = await screen.findByText('No host is answering on this machine')
    const said = banner.parentElement?.textContent ?? ''
    expect(said).toMatch(/This host cannot be contacted right now\. The steps below/)
    // The categories are still guided, because they are facts about this Mac rather than about
    // a host that happens to be running.
    expect(screen.getByTestId('setup-permission-accessibility')).toBeInTheDocument()
  })
})

describe('what a restart is asked for, and what a record is about', () => {
  it('waits for every grant that stands behind a capability before it asks for a restart', async () => {
    const { controls } = start()
    await screen.findByTestId('setup-identity')
    await goTo('permissions')
    // Reading the accessibility tree is behind two grants. One of them is not enough.
    await userEvent.click(screen.getByTestId('setup-open-accessibility'))
    await waitFor(() => {
      expect(controls.openedPanes).toEqual(['accessibility'])
    })
    await goTo('capabilities')
    await userEvent.click(screen.getByTestId('setup-recheck'))
    await waitFor(() => {
      expect(screen.getByTestId('setup-recheck').textContent).toBe('Check again')
    })
    expect(screen.getByTestId('setup-state-desktop.accessibility').textContent).toBe(
      'Permission required'
    )

    // Both of them, and the answer becomes the one that tells the person what to do next.
    await goTo('permissions')
    await userEvent.click(screen.getByTestId('setup-open-automation'))
    await waitFor(() => {
      expect(controls.openedPanes).toEqual(['accessibility', 'automation'])
    })
    await goTo('capabilities')
    await userEvent.click(screen.getByTestId('setup-recheck'))
    await waitFor(() => {
      expect(screen.getByTestId('setup-state-desktop.accessibility').textContent).toBe(
        'Restart required'
      )
    })
    // The screen capture is behind a grant nobody was sent to, so it stays what it was.
    expect(screen.getByTestId('setup-state-desktop.screen_capture').textContent).toBe(
      'Permission required'
    )
  })

  it('names what each answer was established about, so one file is not read as a grant', async () => {
    start()
    await screen.findByTestId('setup-identity')
    await goTo('permissions')
    const about = screen.getByTestId('setup-about-desktop.authorised_file_read')
    expect(about.textContent).toMatch(/kalareach-check\.txt/)
    expect(screen.getByTestId('setup-caveat-full_disk_access').textContent).toMatch(
      /a file outside the places macOS protects establishes nothing/
    )
  })

  it('says it installs nothing itself, and names the command where there is one', async () => {
    start()
    await screen.findByTestId('setup-identity')
    await goTo('host')
    expect(screen.getByTestId('setup-panel-host').textContent).toMatch(
      /Nothing on this screen installs anything/
    )
    // The one offer with a command of its own names it; the others do not invent one.
    expect(screen.getByTestId('setup-install-terminal_profile').textContent).toMatch(
      /kr shell install/
    )
    expect(screen.getByTestId('setup-install-gui_host').textContent).not.toMatch(/kr host install/)
    await userEvent.click(within(screen.getByTestId('setup-install-gui_host')).getByRole('switch'))
    await goTo('ready')
    const commands = screen.getByTestId('setup-commands')
    expect(commands.textContent).toMatch(/installed or downloaded anything/)
    expect(commands.textContent).toMatch(/The graphical host/)
  })

  it('shows the model choice on its own, with nothing else chosen', async () => {
    start()
    await screen.findByTestId('setup-identity')
    await goTo('host')
    await userEvent.click(screen.getByTestId('setup-model-download'))
    await goTo('ready')
    expect(screen.queryByTestId('setup-nothing-chosen')).toBeNull()
    expect(screen.getByTestId('setup-commands').textContent).toMatch(/The default local model/)
  })
})
