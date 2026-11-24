/**
 * What each check does, said before any of them is asked for, one table per platform.
 *
 * A line here is read by a person who has not yet agreed to a run, so it has to be true of the
 * route the check takes on this desktop and of no other. That is why the table is by route and not
 * by operating system: the same Linux machine takes its screen image one way on X11 and another on
 * Wayland, and a line that fits one would be a false description of the other.
 *
 * A route has a line for a check only where an operation exists for it. A check with no operation
 * on a route is not listed for that route, because listing "asks the accessibility tree" on a
 * desktop where nothing asks it would be a claim about something that does not happen. Each part
 * that adds an operation adds its route's lines here, in the same change.
 */

import type { SetupPlatform } from '../host/port'

/** Where a check's operation goes: the platform, and on Linux the display server that decides it. */
export type CheckRoute = 'macos' | 'x11' | 'wayland' | 'linux' | 'windows' | 'other'

/** One check as the person reads it. */
export interface DisclosedCheck {
  /** What the check is called. */
  readonly name: string
  /** The capability its answer is a record of. */
  readonly capability: string
  /** What it does. */
  readonly performs: string
  /** What it touches, and what it leaves alone. */
  readonly effect: string
}

/** What a check says on one route. */
interface Lines {
  readonly performs: string
  readonly effect: string
}

/** One check, and the lines it has on each route where an operation exists. */
interface CheckLines {
  readonly name: string
  readonly capability: string
  /** The same words on every route. */
  readonly all?: Lines
  /** Words for one route; a route with neither these nor `all` does not list the check. */
  readonly by?: Readonly<Partial<Record<CheckRoute, Lines>>>
}

/**
 * On macOS the line says the image is removed before the check answers. The route tries that
 * removal and names a file it could not remove, as the Linux routes do, so the line says more than
 * the route does. Its words stay as they are.
 */
const IMAGE_FILE = "Writes the image into the check's own directory and removes it before answering."

/**
 * On Linux the removal is attempted and can fail, and the answer then names the file it left, so
 * the line says no more than that: a promise to remove it would be untrue exactly there.
 */
const LINUX_IMAGE_FILE =
  "Writes the image into the check's own directory and tries to remove it before answering. If it " +
  'cannot remove it, the answer names the file.'

/** The checks, in the order they are shown. */
const CHECKS: readonly CheckLines[] = [
  {
    name: 'Read a file you authorised',
    capability: 'desktop.authorised_file_read',
    all: {
      performs: 'Opens a file you chose and reads the first few thousand bytes of it.',
      effect: 'Reads that file and writes nothing. With no file chosen it reads nothing and says so.'
    }
  },
  {
    name: 'Take a screen image',
    capability: 'desktop.screen_capture',
    by: {
      macos: {
        performs: 'Takes one image of the desktop and measures it.',
        effect: IMAGE_FILE
      },
      x11: {
        performs:
          'With a local X display set for the worker and a screen-capture tool installed, takes ' +
          'one image of the whole X screen, every monitor on it, and reads it into memory to ' +
          'measure it. In any other case it takes no image.',
        effect: LINUX_IMAGE_FILE
      },
      wayland: {
        performs:
          'With a Wayland display set for the worker, on a compositor this check knows to offer ' +
          'its screen-copy protocol, with its screen-copy tool installed, asks it for one image ' +
          'of every output and reads it into memory to measure it. In any other case it takes ' +
          'no image.',
        effect: LINUX_IMAGE_FILE
      }
    }
  },
  {
    name: 'Find an element',
    capability: 'desktop.accessibility',
    by: {
      macos: {
        performs: 'Asks the accessibility tree for the name of one element.',
        effect: 'Reads the tree. Selects nothing, moves nothing, clicks nothing.'
      }
    }
  },
  {
    name: 'Open an application',
    capability: 'desktop.application_launch',
    by: {
      macos: {
        performs: 'Starts one new background instance of an application and ends the one it started.',
        effect: 'Touches nothing you already have open.'
      }
    }
  },
  {
    name: 'Send a keystroke',
    capability: 'desktop.input_injection',
    all: {
      performs: 'Delivers one keystroke.',
      effect:
        'This one changes something, so it runs only inside a test context of its own. Without ' +
        'one it is not run at all, and nothing is claimed about it either way.'
    }
  }
]

/**
 * The route a check takes on this desktop.
 *
 * `displayServer` is what the host named for this login's desktop, and it matters only on Linux. A
 * Linux desktop whose display server the host could not name has no route of its own, so no check
 * is listed for it that needs one.
 */
export function routeOf(platform: SetupPlatform | null, displayServer: string | null): CheckRoute {
  switch (platform) {
    case 'macos':
      return 'macos'
    case 'windows':
      return 'windows'
    case 'linux':
      if (displayServer === 'x11') return 'x11'
      return displayServer === 'wayland' ? 'wayland' : 'linux'
    default:
      return 'other'
  }
}

/** The checks listed for one route, each with the words that are true there. */
export function disclosedChecks(route: CheckRoute): readonly DisclosedCheck[] {
  return CHECKS.flatMap((check) => {
    const lines = check.by?.[route] ?? check.all
    return lines
      ? [{ name: check.name, capability: check.capability, performs: lines.performs, effect: lines.effect }]
      : []
  })
}

/** What the list of checks says at its foot, before a run. */
export function checksNote(platform: SetupPlatform | null): string {
  const shared =
    'None of them sends input to an application you did not ask about, and none of them ' +
    'changes anything you own.'
  return platform === 'macos'
    ? `${shared} macOS may ask you to allow something while they run, and a run can take about two minutes.`
    : `${shared} A run can take about two minutes.`
}

/** What the page says about a run that is going. */
export function runningLine(platform: SetupPlatform | null): string {
  return platform === 'macos'
    ? "The checks are running in a session's worker. macOS may ask you to allow something " +
        'while they do, and they can take about two minutes.'
    : "The checks are running in a session's worker, and they can take about two minutes."
}
