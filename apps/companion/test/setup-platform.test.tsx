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
import { grantWasOffered, setupLinkFor } from '../src/setup/platform'
import setupStylesheet from '../src/setup/setup.css?raw'
import baseStylesheet from '../src/styles/base.css?raw'
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

/**
 * The whole window's text, in one string, where a macOS word would be found: the side bar and the
 * toasts are as much of what a person reads as the setup page.
 */
function pageText(): string {
  return document.body.textContent
}

const STEP_IDS = ['identity', 'permissions', 'capabilities', 'host', 'ready'] as const

/** Tab until the element has focus, and say whether it ever did. */
async function reachByKeyboard(testId: string): Promise<boolean> {
  for (let presses = 0; presses < 80; presses += 1) {
    if (document.activeElement === screen.getByTestId(testId)) return true
    await userEvent.tab()
  }
  return document.activeElement === screen.getByTestId(testId)
}

/** The rules inside the first reduced-motion media query of a stylesheet, without comments. */
function reducedMotionRules(source: string): string {
  const css = source.replace(/\/\*[\s\S]*?\*\//g, '')
  const opened = css.indexOf('@media (prefers-reduced-motion: reduce)')
  if (opened < 0) return ''
  const from = css.indexOf('{', opened) + 1
  let depth = 1
  let index = from
  while (depth > 0 && index < css.length) {
    if (css[index] === '{') depth += 1
    if (css[index] === '}') depth -= 1
    index += 1
  }
  return css.slice(from, index - 1)
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
    // The side bar names the page for this Mac, as it always did, once the platform is read.
    expect(await screen.findByRole('button', { name: 'Set up this Mac' })).toHaveAttribute(
      'aria-current',
      'page'
    )
    await goTo('permissions')
    for (const pane of ['accessibility', 'screen_recording', 'full_disk_access', 'automation']) {
      expect(screen.getByTestId(`setup-permission-${pane}`)).toBeInTheDocument()
    }
  })

  it.each(OTHER_DESKTOPS)('shows no macOS card and no macOS word on %s', async (desktop) => {
    start(desktop)
    await screen.findByTestId('setup-identity')
    expect(screen.getByRole('heading', { level: 1 }).textContent).toBe('Set up KalaReach')
    // The side bar says the same: "this Mac" is not a thing on another desktop.
    expect(screen.getByRole('button', { name: 'Set up KalaReach' })).toHaveAttribute(
      'aria-current',
      'page'
    )
    expect(screen.queryByRole('button', { name: /this Mac/ })).toBeNull()
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
    expect(screen.getByRole('button', { name: 'Set up KalaReach' })).toBeInTheDocument()
    await goTo('permissions')
    expect(document.querySelector('[data-testid^="setup-permission-"]')).toBeNull()
    expect(pageText()).not.toMatch(/macOS|Mac\b|System Settings/)
  })

  it('shows nothing of any platform while the application is being read, then its own page', async () => {
    let release: () => void = () => undefined
    const held = new Promise<void>((resolve) => {
      release = resolve
    })
    start('macos', (port) => ({
      ...port,
      setupIdentity: async () => {
        await held
        return port.setupIdentity()
      }
    }))
    expect(await screen.findByText('Reading this application…')).toBeInTheDocument()
    expect(screen.getByRole('heading', { level: 1 }).textContent).toBe('Set up KalaReach')
    expect(screen.queryByTestId('setup-step-permissions')).toBeNull()
    expect(screen.queryByTestId('setup-next')).toBeNull()
    expect(document.querySelector('[data-testid^="setup-permission-"]')).toBeNull()
    expect(pageText()).not.toMatch(/macOS|Mac\b|System Settings/)
    release()
    expect(await screen.findByTestId('setup-identity')).toBeInTheDocument()
    expect(screen.getByRole('heading', { level: 1 }).textContent).toBe(
      'Set up KalaReach on this Mac'
    )
    expect(screen.getByTestId('setup-step-permissions').textContent).toMatch(/Permissions/)
  })

  // The application's own answer and the host's answer are two readings. One failing must not take
  // away what the other said: on a Mac that is the difference between the permission cards being
  // there and not.
  it('keeps the macOS cards when only the host’s reading of this machine fails', async () => {
    start('macos', (port) => ({
      ...port,
      environmentCapabilities: () => Promise.reject(new Error('the host did not answer'))
    }))
    expect(await screen.findByTestId('setup-signature')).toBeInTheDocument()
    expect(screen.getByRole('heading', { level: 1 }).textContent).toBe(
      'Set up KalaReach on this Mac'
    )
    await goTo('permissions')
    for (const pane of ['accessibility', 'screen_recording', 'full_disk_access', 'automation']) {
      expect(screen.getByTestId(`setup-permission-${pane}`)).toBeInTheDocument()
    }
  })

  it('shows the host’s records when only the first reading of the application fails, and its cards once it is read', async () => {
    let failing = true
    start('macos', (port) => ({
      ...port,
      setupIdentity: () =>
        failing
          ? Promise.reject(new Error('the application could not be read'))
          : port.setupIdentity()
    }))
    await waitFor(() => {
      expect(screen.getByTestId('setup-step-permissions')).toBeInTheDocument()
    })
    // Nothing of macOS while the application is unread, and the host's records all the same.
    expect(screen.getByRole('heading', { level: 1 }).textContent).toBe('Set up KalaReach')
    await goTo('capabilities')
    expect(await screen.findByTestId('setup-capability-desktop.screen_capture')).toBeInTheDocument()
    failing = false
    await userEvent.click(screen.getByTestId('setup-recheck'))
    await waitFor(() => {
      expect(screen.getByRole('heading', { level: 1 }).textContent).toBe(
        'Set up KalaReach on this Mac'
      )
    })
    await goTo('permissions')
    for (const pane of ['accessibility', 'screen_recording', 'full_disk_access', 'automation']) {
      expect(screen.getByTestId(`setup-permission-${pane}`)).toBeInTheDocument()
    }
  })

  // KR-REQ-03.30: what a check does depends on the platform, and the list a person reads before a
  // run is worded for it. The host's records can be read while the application is not, and that
  // must not leave a run on offer that the list does not describe.
  it('starts no check while the platform is not known, and lists them all once it is read', async () => {
    let failing = true
    const controls = start('macos', (port) => ({
      ...port,
      setupIdentity: () =>
        failing
          ? Promise.reject(new Error('the application could not be read'))
          : port.setupIdentity()
    }))
    await waitFor(() => {
      expect(screen.getByTestId('setup-step-capabilities')).toBeInTheDocument()
    })
    await goTo('capabilities')
    const run = await screen.findByTestId('setup-run-checks')
    // Pressing the control asks for nothing, and when a list or a run button were still reached it
    // is pressed too: no check request is made from anywhere on the page.
    await userEvent.click(run)
    const sheetRun = screen.queryByTestId('setup-checks-run')
    if (sheetRun) await userEvent.click(sheetRun)
    expect(controls.checkRuns).toEqual([])
    expect(screen.queryByTestId('setup-effects')).toBeNull()
    expect(run).toBeDisabled()
    expect(run).toHaveAttribute('aria-describedby', 'setup-run-unavailable')
    expect(screen.getByTestId('setup-run-unavailable').textContent).toBe(
      'The checks cannot run until this app has read which system it runs on, because what they ' +
        'do depends on it. Use “Read again” to try once more.'
    )
    // Reading again is still on offer, and once the application is read the list is the whole one.
    expect(screen.getByTestId('setup-recheck')).toBeEnabled()
    failing = false
    await userEvent.click(screen.getByTestId('setup-recheck'))
    await waitFor(() => {
      expect(screen.getByTestId('setup-run-checks')).toBeEnabled()
    })
    expect(screen.queryByTestId('setup-run-unavailable')).toBeNull()
    expect(screen.getByTestId('setup-run-checks')).not.toHaveAttribute('aria-describedby')
    await userEvent.click(screen.getByTestId('setup-run-checks'))
    const sheet = await screen.findByTestId('setup-effects')
    const items = within(sheet).getAllByRole('listitem')
    const whole = disclosedChecks('macos')
    expect(items).toHaveLength(whole.length)
    whole.forEach((check, index) => {
      expect(items[index]?.textContent).toBe(`${check.name}${check.performs}${check.effect}`)
    })
    expect(controls.checkRuns).toEqual([])
    await userEvent.click(screen.getByTestId('setup-checks-run'))
    await waitFor(() => {
      expect(controls.checkRuns).toHaveLength(1)
    })
  })

  it('keeps the platform the first reading named, whatever a later reading says', async () => {
    let later = false
    let reads = 0
    start('x11', (port) => ({
      ...port,
      setupIdentity: async () => {
        reads += 1
        const identity = await port.setupIdentity()
        return later ? { ...identity, platform: 'macos' as const } : identity
      }
    }))
    await screen.findByTestId('setup-identity')
    const before = reads
    later = true
    await goTo('capabilities')
    await userEvent.click(screen.getByTestId('setup-recheck'))
    await waitFor(() => {
      expect(screen.getByTestId('setup-recheck').textContent).toBe('Read again')
    })
    expect(reads).toBeGreaterThan(before)
    expect(screen.getByRole('heading', { level: 1 }).textContent).toBe('Set up KalaReach')
    await goTo('permissions')
    expect(document.querySelector('[data-testid^="setup-permission-"]')).toBeNull()
    expect(pageText()).not.toMatch(/macOS|Mac\b|System Settings/)
  })

  it('names the side bar’s setup link for this Mac on macOS and plainly everywhere else', () => {
    expect(setupLinkFor('macos')).toBe('Set up this Mac')
    for (const platform of ['linux', 'windows', 'other', null] as const) {
      expect(setupLinkFor(platform), String(platform)).toBe('Set up KalaReach')
    }
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
    const screenCheck = (route: Parameters<typeof disclosedChecks>[0]) =>
      disclosedChecks(route).find((check) => check.capability === 'desktop.screen_capture')
    expect(screenCheck('macos')?.performs).toBe('Takes one image of the desktop and measures it.')
    expect(screenCheck('x11')?.performs).toBe(
      'With a local X display set for the worker and a screen-capture tool installed, takes one ' +
        'image of the whole X screen, every monitor on it, and reads it into memory to measure ' +
        'it. In any other case it takes no image.'
    )
    expect(screenCheck('wayland')?.performs).toBe(
      'With a Wayland display set for the worker, on a compositor this check knows to offer its ' +
        'screen-copy protocol, with its screen-copy tool installed, asks it for one image of ' +
        'every output and reads it into memory to measure it. In any other case it takes no image.'
    )
  })

  // The image's file is removed on a best effort, and the answer names one that was not: a line
  // that said the check "removes it" or "keeps nothing" would be untrue exactly where it matters.
  it('says the check tries to remove the image, and names a file it could not remove', () => {
    const effect = (route: Parameters<typeof disclosedChecks>[0]): string | undefined =>
      disclosedChecks(route).find((check) => check.capability === 'desktop.screen_capture')?.effect
    expect(effect('macos')).toBe(
      "Writes the image into the check's own directory and removes it before answering."
    )
    for (const route of ['x11', 'wayland'] as const) {
      expect(effect(route), route).toBe(
        "Writes the image into the check's own directory and tries to remove it before " +
          'answering. If it cannot remove it, the answer names the file.'
      )
    }
    for (const route of ['x11', 'wayland'] as const) {
      const lines = disclosedChecks(route).flatMap((check) => [check.performs, check.effect])
      expect(lines.join(' '), route).not.toMatch(/keeps nothing|removes it before answering/)
    }
  })

  it.each([
    ['x11', /whole X screen, every monitor on it/],
    [
      'wayland',
      /screen-copy protocol, with its screen-copy tool installed, asks it for one image of every output/
    ]
  ] as const)('reads the %s lines before anything is asked of the host', async (desktop, line) => {
    const controls = start(desktop)
    await screen.findByTestId('setup-identity')
    // On the step that lists them, with no run offered from it.
    await goTo('permissions')
    const listed = screen.getByTestId('setup-panel-permissions').textContent
    expect(listed).toMatch(line)
    expect(listed).toMatch(/tries to remove it before answering/)
    expect(listed).not.toMatch(/main display|accessibility tree|background instance/i)
    // And on the sheet that asks for the run, which says the same and asks for nothing by being read.
    await goTo('capabilities')
    await userEvent.click(screen.getByTestId('setup-run-checks'))
    const effects = await screen.findByTestId('setup-effects')
    expect(effects.textContent).toMatch(line)
    expect(effects.textContent).toMatch(/tries to remove it before answering/)
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

  // The words of the macOS checks as the page said them before the lines moved into a table per
  // platform: a person on a Mac reads exactly these, and a check added for another platform must not
  // change one of them.
  const MACOS_CHECKS = [
    {
      name: 'Read a file you authorised',
      performs: 'Opens a file you chose and reads the first few thousand bytes of it.',
      effect: 'Reads that file and writes nothing. With no file chosen it reads nothing and says so.'
    },
    {
      name: 'Take a screen image',
      performs: 'Takes one image of the desktop and measures it.',
      effect: "Writes the image into the check's own directory and removes it before answering."
    },
    {
      name: 'Find an element',
      performs: 'Asks the accessibility tree for the name of one element.',
      effect: 'Reads the tree. Selects nothing, moves nothing, clicks nothing.'
    },
    {
      name: 'Open an application',
      performs: 'Starts one new background instance of an application and ends the one it started.',
      effect: 'Touches nothing you already have open.'
    },
    {
      name: 'Send a keystroke',
      performs: 'Delivers one keystroke.',
      effect:
        'This one changes something, so it runs only inside a test context of its own. Without ' +
        'one it is not run at all, and nothing is claimed about it either way.'
    }
  ] as const

  it('keeps every macOS line and its note exactly as they were', async () => {
    expect(
      disclosedChecks('macos').map(({ name, performs, effect }) => ({ name, performs, effect }))
    ).toEqual(MACOS_CHECKS)
    start('macos')
    await screen.findByTestId('setup-identity')
    await goTo('capabilities')
    await userEvent.click(screen.getByTestId('setup-run-checks'))
    const effects = await screen.findByTestId('setup-effects')
    // What the person reads on the sheet, entry by entry: the name, what it does, what it touches.
    const read = within(effects)
      .getAllByRole('listitem')
      .map((entry) => ({
        name: entry.querySelector('strong')?.textContent,
        performs: entry.querySelectorAll('p')[0]?.textContent,
        effect: entry.querySelectorAll('p')[1]?.textContent
      }))
    expect(read).toEqual(MACOS_CHECKS)
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

  // A capability has one record for each subject it was established about, so a check can have
  // several, and each says what the host said of its own subject.
  it('shows every record the host holds for one check, each with its own state and reason', async () => {
    const second = 'a second tool was run, and the screen came back'
    start('x11', (port) => ({
      ...port,
      environmentCapabilities: async (request) => {
        const answer = await port.environmentCapabilities(request)
        const records = answer.desktop.records.flatMap((record) =>
          record.capability === 'desktop.screen_capture'
            ? [
                record,
                {
                  ...record,
                  state: 'qualified_available' as const,
                  evidence_source: 'disclosed_probe' as const,
                  disabled_reason: second,
                  identity: { ...record.identity, binary: '/usr/bin/maim' }
                }
              ]
            : [record]
        )
        return { ...answer, desktop: { ...answer.desktop, records } }
      }
    }))
    await screen.findByTestId('setup-identity')
    await goTo('permissions')
    const card = screen.getByTestId('setup-disclosed-desktop.screen_capture')
    expect(
      within(card)
        .getAllByTestId('setup-disclosed-state-desktop.screen_capture')
        .map((badge) => badge.textContent)
    ).toEqual(['Not checked', 'Ready'])
    expect(
      within(card)
        .getAllByTestId('setup-disclosed-reason-desktop.screen_capture')
        .map((reason) => reason.textContent)
    ).toEqual(['this process holds no X11 display; a worker’s own context is what a check reads', second])
    expect(card.textContent).toMatch(/\/usr\/bin\/maim/)
    // A check with one record keeps its single badge and reason.
    const file = screen.getByTestId('setup-disclosed-desktop.authorised_file_read')
    expect(within(file).getAllByTestId('setup-disclosed-state-desktop.authorised_file_read')).toHaveLength(1)
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
    expect(stateMeaning('permission_required', 'disclosed_probe', 'macos', 'desktop.screen_capture')).toBe(
      'macOS refused it. The grant is yours to give.'
    )
    expect(
      stateMeaning('permission_required', 'platform_query', 'macos', 'desktop.authorised_file_read')
    ).toBe('This needs a grant macOS has not given. The grant is yours to give.')
  })

  it('gives the file’s own sentence to the file read and to no other capability', () => {
    for (const platform of ['linux', 'windows', 'other', null] as const) {
      for (const evidence of ['disclosed_probe', 'platform_query'] as const) {
        expect(
          stateMeaning('permission_required', evidence, platform, 'desktop.authorised_file_read')
        ).toBe("The file's own access settings refused it. Changing them is yours to do.")
        for (const capability of [
          'desktop.screen_capture',
          'desktop.accessibility',
          'desktop.application_launch',
          'desktop.input_injection',
          'desktop.display_server'
        ]) {
          expect(
            stateMeaning('permission_required', evidence, platform, capability),
            `${capability} on ${platform}`
          ).toBeNull()
        }
      }
    }
  })

  it('keeps the host’s reason for another capability’s refusal and adds no sentence', async () => {
    const reason = 'no X11 display is set for this process, and the tool it found needs one'
    const controls = start('x11', (port) => ({
      ...port,
      environmentCapabilities: async (request) => {
        const answer = await port.environmentCapabilities(request)
        return {
          ...answer,
          desktop: {
            ...answer.desktop,
            records: answer.desktop.records.map((record) =>
              record.capability === 'desktop.screen_capture'
                ? {
                    ...record,
                    state: 'permission_required' as const,
                    evidence_source: 'platform_query' as const,
                    disabled_reason: reason
                  }
                : record
            )
          }
        }
      }
    }))
    await screen.findByTestId('setup-identity')
    // Both refusals on one page: the file's own, and a capability that is not a file.
    controls.revokePermission('desktop.authorised_file_read')
    await goTo('capabilities')
    await userEvent.click(screen.getByTestId('setup-recheck'))
    await waitFor(() => {
      expect(screen.getByTestId('setup-state-desktop.authorised_file_read').textContent).toBe(
        'Permission required'
      )
    })
    const card = screen.getByTestId('setup-capability-desktop.screen_capture')
    expect(screen.getByTestId('setup-state-desktop.screen_capture').textContent).toBe(
      'Permission required'
    )
    expect(screen.getByTestId('setup-reason-desktop.screen_capture').textContent).toBe(reason)
    expect(card.textContent).not.toMatch(/access settings|macOS|grant is yours to give/)
    // The one paragraph of the card's body that is not the host's reason is the "about" line, and
    // this record has none: the reason is the only sentence the card has.
    expect(card.querySelectorAll('.card-body > p')).toHaveLength(1)
    // The file read, refused on the same page, keeps its own sentence.
    expect(
      within(screen.getByTestId('setup-capability-desktop.authorised_file_read')).getByText(
        "The file's own access settings refused it. Changing them is yours to do."
      )
    ).toBeInTheDocument()
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
  it('reaches each step, and moves through them all, with the keyboard alone', async () => {
    start('x11')
    await screen.findByTestId('setup-identity')
    // Each step from the rail, in order, then back again.
    for (const id of [...STEP_IDS, ...[...STEP_IDS].reverse()]) {
      expect(await reachByKeyboard(`setup-step-${id}`), id).toBe(true)
      await userEvent.keyboard('{Enter}')
      expect(await screen.findByTestId(`setup-panel-${id}`)).toBeInTheDocument()
      expect(screen.getByTestId(`setup-step-${id}`)).toHaveAttribute('aria-current', 'step')
    }
    // Then forward from the first step with Continue alone.
    expect(await reachByKeyboard('setup-step-identity')).toBe(true)
    await userEvent.keyboard('{Enter}')
    for (const id of STEP_IDS.slice(1)) {
      expect(await reachByKeyboard('setup-next'), id).toBe(true)
      await userEvent.keyboard('{Enter}')
      expect(await screen.findByTestId(`setup-panel-${id}`)).toBeInTheDocument()
      expect(screen.getByTestId(`setup-step-${id}`)).toHaveAttribute('aria-current', 'step')
    }
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

  it('removes the travel of what the page moves under reduced motion and keeps the fade', async () => {
    start('x11')
    await screen.findByTestId('setup-identity')
    await goTo('permissions')
    // The step adds no motion of its own: nothing on it carries an inline style.
    expect(screen.getByTestId('setup-panel-permissions').querySelectorAll('[style]')).toHaveLength(0)
    // What the page moves is the panel's arrival, an animation, and the evidence row's grid rows.
    const outside = setupStylesheet.slice(setupStylesheet.indexOf('@media (prefers-reduced-motion'))
    const moving = setupStylesheet.replace(outside, '')
    expect(moving.match(/^\s*animation:/gm)).toHaveLength(1)
    expect(moving).toMatch(/\.setup-body \{[^}]*animation: setup-step-in/)
    expect(moving).toMatch(/\.setup-evidence \{[^}]*transition:\s+grid-template-rows/)
    // The shared rule takes every animation away, and wins over a class's own animation only
    // because it is `!important`.
    expect(reducedMotionRules(baseStylesheet)).toMatch(/\*,[^{]*\{[^}]*animation: none !important;/)
    // The evidence row keeps its fade and loses its travel.
    const reduced = reducedMotionRules(setupStylesheet)
    expect(reduced).toMatch(
      /\.setup-evidence\[data-open='true'\] \{\s+transition: opacity var\(--state\) var\(--ease-out\);\s+\}/
    )
    expect(reduced).not.toMatch(/grid-template-rows|transform|translate|scale|animation/)
  })
})
