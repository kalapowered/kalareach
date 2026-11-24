/**
 * The setup assistant on each platform.
 *
 * Setup guides a person through macOS's permission panes, and nothing else has panes to guide
 * anybody through. These cases drive the screen the desktop shell loads, against a scripted host
 * that stands on each desktop in turn, and check the one thing the guard is for: a person on
 * another platform is shown no macOS card, is told nothing that is only true of macOS, and reads,
 * before any run, a line for each check that is true of the route the check takes on their desktop.
 */

import { describe, expect, it } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { App } from '../src/App'
import { AppProvider } from '../src/app/state'
import { fakeHost, type FakeDesktop, type FakeHostControls } from '../src/host/fake'
import type { HostPort, SetupPlatform } from '../src/host/port'
import { disclosedChecks, routeOf } from '../src/setup/disclosure'
import { grantWasOffered } from '../src/setup/platform'
import setupStylesheet from '../src/setup/setup.css?raw'
import { stateMeaning } from '../src/setup/states'

/** The page the desktop shell loads, on one desktop, with the host's identity read as given. */
function start(
  desktop: FakeDesktop,
  settle: (port: HostPort) => HostPort = (port) => port
): FakeHostControls {
  const host = fakeHost()
  host.controls.setDesktop(desktop)
  render(
    <AppProvider port={settle(host.port)} initialPlace={{ view: 'setup' }}>
      <App />
    </AppProvider>
  )
  return host.controls
}

async function goTo(step: string): Promise<void> {
  await userEvent.click(screen.getByTestId(`setup-step-${step}`))
  await screen.findByTestId(`setup-panel-${step}`)
}

/** The page's text, in one string, where a macOS word would be found. */
function pageText(): string {
  return screen.getByTestId('setup').textContent
}

const OTHER_DESKTOPS: readonly FakeDesktop[] = ['x11', 'wayland', 'windows']

// KR-REQ-03.29: the setup assistant shows a macOS permission card on macOS and on no other
// platform, and says nothing that is only true of macOS anywhere else.
describe('which platform the page is shown for', () => {
  it('shows the four macOS permission cards on macOS and its own words', async () => {
    start('macos')
    await screen.findByTestId('setup-identity')
    expect(screen.getByRole('heading', { level: 1 }).textContent).toBe(
      'Set up KalaReach on this Mac'
    )
    expect(screen.getByTestId('setup-step-permissions').textContent).toMatch(/Permissions/)
    expect(screen.getByTestId('setup-signature')).toBeInTheDocument()
    await goTo('permissions')
    for (const pane of ['accessibility', 'screen_recording', 'full_disk_access', 'automation']) {
      expect(screen.getByTestId(`setup-permission-${pane}`)).toBeInTheDocument()
    }
  })

  it.each(OTHER_DESKTOPS)('shows no macOS card and no macOS word on %s', async (desktop) => {
    start(desktop)
    await screen.findByTestId('setup-identity')
    expect(screen.getByRole('heading', { level: 1 }).textContent).toBe('Set up KalaReach')
    // The identity says which application this is, and nothing about a grant being filed.
    expect(screen.queryByTestId('setup-signature')).toBeNull()
    expect(screen.queryByTestId('setup-ceiling-identity')).toBeNull()
    expect(pageText()).not.toMatch(/macOS|Mac\b|signed application|Grants given now/)
    expect(screen.getByText('Which application is this?')).toBeInTheDocument()

    expect(screen.getByTestId('setup-step-permissions').textContent).toMatch(/The checks/)
    await goTo('permissions')
    expect(screen.getByText('What will each check do here?')).toBeInTheDocument()
    expect(document.querySelector('[data-testid^="setup-permission-"]')).toBeNull()
    expect(screen.queryByRole('button', { name: /System Settings/ })).toBeNull()
    expect(screen.queryByTestId('setup-explain-checks')).toBeNull()
    expect(pageText()).not.toMatch(/macOS|System Settings|Full Disk Access|Automation/)
  })

  it('shows no macOS card while the application has not been read, and when it cannot be', async () => {
    const controls = start('macos', (port) => ({
      ...port,
      setupIdentity: () => Promise.reject(new Error('the application could not be read'))
    }))
    expect(controls.checkRuns).toEqual([])
    await waitFor(() => {
      expect(screen.getByTestId('setup-step-permissions')).toBeInTheDocument()
    })
    expect(screen.getByRole('heading', { level: 1 }).textContent).toBe('Set up KalaReach')
    await goTo('permissions')
    expect(document.querySelector('[data-testid^="setup-permission-"]')).toBeNull()
    expect(pageText()).not.toMatch(/macOS|Mac\b|System Settings/)
  })
})

// KR-REQ-03.29: a person reads what each check does on their own desktop before any run, and each
// line is true of the route the check takes there.
describe('what each check says it does, before it is run', () => {
  it('lists, for each route, only the checks that have an operation on it', () => {
    const names = (route: Parameters<typeof disclosedChecks>[0]): string[] =>
      disclosedChecks(route).map((check) => check.name)
    expect(names('macos')).toEqual([
      'Read a file you authorised',
      'Take a screen image',
      'Find an element',
      'Open an application',
      'Send a keystroke'
    ])
    const screenRoute = ['Read a file you authorised', 'Take a screen image', 'Send a keystroke']
    expect(names('x11')).toEqual(screenRoute)
    expect(names('wayland')).toEqual(screenRoute)
    // A Linux desktop the host could not name a display server for, and the platforms that have
    // no operation yet: nothing is listed that does not happen.
    const readOnly = ['Read a file you authorised', 'Send a keystroke']
    expect(names('linux')).toEqual(readOnly)
    expect(names('windows')).toEqual(readOnly)
    expect(names('other')).toEqual(readOnly)
  })

  it('picks the route from the platform and, on Linux, from the display server the host named', () => {
    const cases: [SetupPlatform | null, string | null, string][] = [
      ['macos', 'quartz', 'macos'],
      ['macos', 'x11', 'macos'],
      ['linux', 'x11', 'x11'],
      ['linux', 'wayland', 'wayland'],
      ['linux', 'unknown', 'linux'],
      ['linux', null, 'linux'],
      ['windows', 'windows_desktop', 'windows'],
      ['other', 'x11', 'other'],
      [null, 'x11', 'other']
    ]
    for (const [platform, server, route] of cases) {
      expect(routeOf(platform, server), `${platform} on ${server}`).toBe(route)
    }
  })

  it('says each line of the screen image for its own route', () => {
    const screenLine = (route: Parameters<typeof disclosedChecks>[0]): string =>
      disclosedChecks(route).find((check) => check.capability === 'desktop.screen_capture')
        ?.performs ?? ''
    expect(screenLine('macos')).toBe('Takes one image of the desktop and measures it.')
    expect(screenLine('x11')).toBe(
      'Takes one image of the whole X screen, every monitor on it, reads it into memory to ' +
        'measure it, and keeps nothing.'
    )
    expect(screenLine('wayland')).toBe(
      'On a compositor that offers its screen-copy protocol, asks it for one image of every ' +
        'output, reads it into memory to measure it, and keeps nothing. On any other ' +
        'compositor it takes no image.'
    )
  })

  it.each([
    ['x11', /whole X screen, every monitor on it/],
    ['wayland', /screen-copy protocol, asks it for one image of every output/]
  ] as const)('reads the %s lines before anything is asked of the host', async (desktop, line) => {
    const controls = start(desktop)
    await screen.findByTestId('setup-identity')
    // On the step that lists them, with no run offered from it.
    await goTo('permissions')
    const listed = screen.getByTestId('setup-panel-permissions').textContent
    expect(listed).toMatch(line)
    expect(listed).not.toMatch(/main display|accessibility tree|background instance/i)
    // And on the sheet that asks for the run, which says the same and asks for nothing by being read.
    await goTo('capabilities')
    await userEvent.click(screen.getByTestId('setup-run-checks'))
    const effects = await screen.findByTestId('setup-effects')
    expect(effects.textContent).toMatch(line)
    expect(effects.textContent).toMatch(/Reads that file and writes nothing/)
    expect(effects.textContent).toMatch(/only inside a test context of its own/)
    expect(effects.textContent).not.toMatch(/accessibility tree|background instance/i)
    expect(screen.getByTestId('setup-effects-note').textContent).toBe(
      'None of them sends input to an application you did not ask about, and none of them ' +
        'changes anything you own. A run can take about two minutes.'
    )
    expect(controls.checkRuns).toEqual([])
    await userEvent.click(screen.getByTestId('setup-checks-not-now'))
    expect(controls.checkRuns).toEqual([])
  })

  it('keeps the macOS lines and its note exactly as they were', async () => {
    start('macos')
    await screen.findByTestId('setup-identity')
    await goTo('capabilities')
    await userEvent.click(screen.getByTestId('setup-run-checks'))
    const effects = await screen.findByTestId('setup-effects')
    expect(effects.textContent).toMatch(/Takes one image of the desktop and measures it/)
    expect(effects.textContent).toMatch(/Asks the accessibility tree for the name of one element/)
    expect(screen.getByTestId('setup-effects-note').textContent).toBe(
      'None of them sends input to an application you did not ask about, and none of them ' +
        'changes anything you own. macOS may ask you to allow something while they run, and a ' +
        'run can take about two minutes.'
    )
  })

  it('says a run is going without a macOS prompt where none exists', async () => {
    const controls = start('x11')
    await screen.findByTestId('setup-identity')
    controls.setChecks({ state: 'running' })
    await goTo('capabilities')
    await userEvent.click(screen.getByTestId('setup-recheck'))
    await waitFor(() => {
      expect(screen.getByTestId('setup-checks-state').dataset.state).toBe('running')
    })
    expect(screen.getByTestId('setup-checks-state').textContent).toBe(
      "The checks are running in a session's worker, and they can take about two minutes."
    )
  })
})

// KR-REQ-03.29: what the host says about each capability is shown beside what its check does,
// in the host's own words, and the page does not turn "no route" into a success.
describe('the route each check has on this desktop', () => {
  it('shows the host reason for the screen image beside its line, and not as ready', async () => {
    start('wayland')
    await screen.findByTestId('setup-identity')
    await goTo('permissions')
    const card = screen.getByTestId('setup-disclosed-desktop.screen_capture')
    expect(within(card).getByText('Take a screen image')).toBeInTheDocument()
    expect(screen.getByTestId('setup-disclosed-reason-desktop.screen_capture').textContent).toBe(
      'no route to the screen is established for this compositor'
    )
    expect(screen.getByTestId('setup-disclosed-state-desktop.screen_capture').textContent).toBe(
      'Not checked'
    )
    expect(card.textContent).not.toMatch(/Ready/)
  })

  it('shows the X11 reason the host gave, word for word', async () => {
    start('x11')
    await screen.findByTestId('setup-identity')
    await goTo('permissions')
    expect(screen.getByTestId('setup-disclosed-reason-desktop.screen_capture').textContent).toBe(
      'this process holds no X11 display; a worker’s own context is what a check reads'
    )
  })

  it('still shows every record the host holds, each on its own card, on the next step', async () => {
    start('x11')
    await screen.findByTestId('setup-identity')
    await goTo('capabilities')
    for (const capability of [
      'desktop.accessibility',
      'desktop.application_launch',
      'desktop.authorised_file_read',
      'desktop.display_server',
      'desktop.input_injection',
      'desktop.screen_capture'
    ]) {
      expect(screen.getByTestId(`setup-capability-${capability}`)).toBeInTheDocument()
    }
    // A check with no operation on this route is not described as one that runs.
    expect(screen.getByTestId('setup-reason-desktop.accessibility').textContent).toBe(
      'no route to the accessibility tree is established here'
    )
  })
})

// KR-REQ-03.29: the refusal a person can undo off macOS is the file's own, and it is said as that.
describe('a file the operating system refused to open', () => {
  it('is said as the file’s own access settings, with no pane to open', async () => {
    const controls = start('x11')
    await screen.findByTestId('setup-identity')
    controls.revokePermission('desktop.authorised_file_read')
    await goTo('capabilities')
    await userEvent.click(screen.getByTestId('setup-recheck'))
    const card = await screen.findByTestId('setup-capability-desktop.authorised_file_read')
    await waitFor(() => {
      expect(screen.getByTestId('setup-state-desktop.authorised_file_read').textContent).toBe(
        'Permission required'
      )
    })
    expect(card.textContent).toMatch(
      /The file's own access settings refused it\. Changing them is yours to do\./
    )
    expect(card.textContent).not.toMatch(/macOS|grant is yours to give/)
    expect(screen.queryByRole('button', { name: /System Settings/ })).toBeNull()
    expect(controls.openedPanes).toEqual([])
    // The same record on the step before, with the same badge.
    await goTo('permissions')
    expect(
      screen.getByTestId('setup-disclosed-state-desktop.authorised_file_read').textContent
    ).toBe('Permission required')
  })

  it('keeps macOS’s own sentence on macOS', () => {
    expect(stateMeaning('permission_required', 'disclosed_probe', 'macos')).toBe(
      'macOS refused it. The grant is yours to give.'
    )
    for (const platform of ['linux', 'windows', 'other', null] as const) {
      expect(stateMeaning('permission_required', 'disclosed_probe', platform)).toBe(
        "The file's own access settings refused it. Changing them is yours to do."
      )
      expect(stateMeaning('permission_required', 'platform_query', platform)).not.toMatch(/macOS/)
    }
  })
})

// KR-REQ-03.29: "restart required" says a grant was given in a settings pane the page sent the
// person to, so it is derived only where the page sends anybody to one.
describe('what asks for a restart', () => {
  const visitedEveryPane = {
    screen_recording: 0,
    accessibility: 0,
    automation: 0,
    full_disk_access: 0
  }

  it('is derived on macOS once every pane behind the capability was visited and read again', () => {
    expect(grantWasOffered('macos', 'desktop.screen_capture', visitedEveryPane, 1)).toBe(true)
    expect(grantWasOffered('macos', 'desktop.screen_capture', {}, 1)).toBe(false)
    expect(grantWasOffered('macos', 'desktop.input_injection', { accessibility: 0 }, 1)).toBe(false)
  })

  it.each(['linux', 'windows', 'other', null] as const)(
    'is never derived on %s, whatever was visited',
    (platform) => {
      expect(grantWasOffered(platform, 'desktop.screen_capture', visitedEveryPane, 5)).toBe(false)
      expect(grantWasOffered(platform, 'desktop.authorised_file_read', visitedEveryPane, 5)).toBe(
        false
      )
    }
  )

  it('never shows a restart on a desktop that sends nobody to a pane', async () => {
    const controls = start('wayland')
    await screen.findByTestId('setup-identity')
    controls.revokePermission('desktop.authorised_file_read')
    await goTo('capabilities')
    await userEvent.click(screen.getByTestId('setup-recheck'))
    await userEvent.click(screen.getByTestId('setup-recheck'))
    await waitFor(() => {
      expect(screen.getByTestId('setup-state-desktop.authorised_file_read').textContent).toBe(
        'Permission required'
      )
    })
    expect(pageText()).not.toMatch(/Restart required|start a new session/)
  })
})

// KR-REQ-03.29: the keyboard path, the announcements and the motion rules of the page are the
// same on every platform.
describe('what stays the same off macOS', () => {
  it('reaches each step with the keyboard alone', async () => {
    start('x11')
    await screen.findByTestId('setup-identity')
    let reached = false
    for (let presses = 0; presses < 30 && !reached; presses += 1) {
      await userEvent.tab()
      reached = document.activeElement === screen.getByTestId('setup-step-permissions')
    }
    expect(reached).toBe(true)
    await userEvent.keyboard('{Enter}')
    expect(await screen.findByTestId('setup-panel-permissions')).toBeInTheDocument()
    expect(screen.getByTestId('setup-step-permissions')).toHaveAttribute('aria-current', 'step')
    await userEvent.click(screen.getByTestId('setup-next'))
    expect(await screen.findByTestId('setup-panel-capabilities')).toBeInTheDocument()
  })

  it('announces where the checks stand, politely, in each state', async () => {
    const controls = start('wayland')
    await screen.findByTestId('setup-identity')
    await goTo('capabilities')
    for (const state of ['not_run', 'running', 'current', 'stale', 'failed'] as const) {
      controls.setChecks({ state, failure: state === 'failed' ? 'no_session' : null })
      await userEvent.click(screen.getByTestId('setup-recheck'))
      await waitFor(() => {
        expect(screen.getByTestId('setup-checks-state').dataset.state).toBe(state)
      })
      expect(screen.getByTestId('setup-checks-state')).toHaveAttribute('aria-live', 'polite')
    }
  })

  it('moves nothing of its own on a step that has no macOS card', async () => {
    start('x11')
    await screen.findByTestId('setup-identity')
    await goTo('permissions')
    // The step adds no motion of its own: what it moves is the shared panel arrival and the
    // evidence row, and the stylesheet takes both out for a person who asked for less motion.
    const panel = screen.getByTestId('setup-panel-permissions')
    expect(panel.querySelectorAll('[style]')).toHaveLength(0)
    const reduced = setupStylesheet.slice(
      setupStylesheet.indexOf('@media (prefers-reduced-motion: reduce)')
    )
    expect(reduced.slice(0, reduced.indexOf('\n}\n'))).toMatch(
      /\.setup-evidence\[data-open='true'\] \{\s+transition: opacity var\(--state\) var\(--ease-out\);/
    )
  })
})
