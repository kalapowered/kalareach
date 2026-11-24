/**
 * What setup says and shows on each platform.
 *
 * The permission cards, the step that guides a person through them and the sentences about a grant
 * are macOS's: a privacy grant there belongs to a signed application and is given in System
 * Settings. No other platform has one that this application can send somebody to, so on every
 * other platform the page shows no such card, says no such sentence, and never tells somebody to
 * restart because of a grant it never sent them to give.
 *
 * Where the platform is not known, because the application has not been read yet or could not be,
 * the page says what is true everywhere and shows nothing of macOS's. Guessing it would put a
 * macOS card in front of a person on another system, which is the one mistake this file prevents.
 */

import type { SetupPlatform } from '../host/port'
import { categoriesFor } from './permissions'

/** Whether this is the one platform whose permissions setup guides a person through. */
export function guidesPermissions(platform: SetupPlatform | null): boolean {
  return platform === 'macos'
}

/** One step of the setup path. */
export interface SetupStep {
  readonly id: 'identity' | 'permissions' | 'capabilities' | 'host' | 'ready'
  /** The name on the progress rail. */
  readonly title: string
  /** The question the step answers, shown under the heading. */
  readonly question: string
}

/** The heading over the whole path. */
export function headingFor(platform: SetupPlatform | null): string {
  return guidesPermissions(platform) ? 'Set up KalaReach on this Mac' : 'Set up KalaReach'
}

/** The five steps, in order, with the second and the first worded for the platform. */
export function stepsFor(platform: SetupPlatform | null): readonly SetupStep[] {
  const macos = guidesPermissions(platform)
  return [
    {
      id: 'identity',
      title: 'This application',
      question: macos ? 'Which application is macOS granting to?' : 'Which application is this?'
    },
    {
      id: 'permissions',
      title: macos ? 'Permissions' : 'The checks',
      question: macos ? 'What does macOS have to allow?' : 'What will each check do here?'
    },
    { id: 'capabilities', title: 'What this machine can do', question: 'And how is that known?' },
    { id: 'host', title: 'How KalaReach runs here', question: 'What should be installed?' },
    { id: 'ready', title: 'Ready', question: 'What did this cost you?' }
  ]
}

/**
 * Whether the person has been to every settings pane behind a capability, and the records have
 * been read again since.
 *
 * Only on a platform where setup sends them to a pane. Where it does not, nothing was offered, so
 * a refusal is never turned into a request to restart for a grant nobody was asked to give.
 */
export function grantWasOffered(
  platform: SetupPlatform | null,
  capability: string,
  visited: Readonly<Record<string, number>>,
  reads: number
): boolean {
  if (!guidesPermissions(platform)) return false
  const governing = categoriesFor(capability)
  // Every grant that governs it, not any one of them: a person who granted Accessibility is still
  // waiting on Automation, and telling them to restart would send them the wrong way.
  return (
    governing.length > 0 &&
    governing.every((category) => {
      const at = visited[category.pane]
      return at !== undefined && at < reads
    })
  )
}
