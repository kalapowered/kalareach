/**
 * The three things a desktop installation offers, and the two it only offers.
 *
 * Section 26 keeps the graphical host, the headless host and a terminal profile as separate
 * offers, because they are separate decisions: somebody who wants a machine that keeps working
 * after they log out wants a different thing from somebody who wants their terminal to know about
 * sessions, and installing all three because one was asked for is how an installer earns
 * suspicion.
 *
 * The other two are offers and nothing more. Automatic sleep is the machine's own policy and
 * KalaReach does not change it quietly, so the setting is presented with what it would do and left
 * off; using battery power as well is a second, separate choice. And the default local model is a
 * download with a size on it, which the person can decline, cancel or turn off for good — and
 * declining it leaves setup working, because a download is not a permission.
 */

import type { ProfilePersistence } from '@kalareach/protocol'

/** One thing a desktop installation can put on this machine. */
export interface Installable {
  /** What the interface calls it. */
  readonly id: 'gui_host' | 'headless_host' | 'terminal_profile'
  /** The name a person reads. */
  readonly name: string
  /** What it does. */
  readonly purpose: string
  /** What it writes on this machine, so the person knows what is being added. */
  readonly installs: string
  /** The execution profile it provides, where it provides one. */
  readonly profile?: ProfilePersistence['profile']
}

/** The three offers, each on its own. */
export const INSTALLABLES: readonly Installable[] = [
  {
    id: 'gui_host',
    name: 'The graphical host',
    purpose:
      'Runs sessions inside your own desktop login, so a tool in a session sees the screen you ' +
      'see and the permissions you granted.',
    installs: 'A per-user login item, started when you log in.',
    profile: 'desktop_bound'
  },
  {
    id: 'headless_host',
    name: 'The headless host',
    purpose:
      'Runs sessions outside the desktop, for work that has nothing to do with a screen and ' +
      'should not be tied to one.',
    installs: 'A per-user background service.',
    profile: 'headless_user'
  },
  {
    id: 'terminal_profile',
    name: 'A terminal profile',
    purpose:
      'Teaches your shell about sessions, so `kr` and your prompt agree about which one you are in.',
    installs: 'One block in your shell startup file, marked so it can be removed again.'
  }
]

/** What a logout does, in the words the assistant shows. */
export const PERSISTENCE_LABEL: Readonly<Record<ProfilePersistence['persistence'], string>> = {
  ends_at_logout: 'Ends when you log out',
  survives_logout: 'Keeps running after you log out',
  available_by_choice: 'Can keep running after you log out, if you choose it',
  no_service_manager: 'This machine has no service manager to ask',
  not_established: 'What a logout does to it is not established here'
}

/** The name of each execution profile. */
export const PROFILE_LABEL: Readonly<Record<ProfilePersistence['profile'], string>> = {
  desktop_bound: 'Desktop-bound sessions',
  headless_user: 'Headless sessions'
}

/** How the person is offered the sleep setting, and what each choice means. */
export interface SleepOffer {
  /** The setting as the host reports it now. */
  readonly setting: 'off' | 'mains_only' | 'battery_too'
  /** What this choice does. */
  readonly meaning: string
}

/** The sleep choices, in the order they are offered. */
export const SLEEP_OFFERS: readonly SleepOffer[] = [
  {
    setting: 'off',
    meaning: 'This machine sleeps when it normally would. KalaReach does nothing about it.'
  },
  {
    setting: 'mains_only',
    meaning:
      'While work you asked for is running and this machine is on mains power, it stays awake. ' +
      'It goes back to sleeping normally the moment that work ends.'
  },
  {
    setting: 'battery_too',
    meaning:
      'The same on battery. This is a separate choice from the one above, because staying awake ' +
      'on battery is a different decision about your machine.'
  }
]

/** The command that changes the sleep setting, which the assistant shows rather than runs. */
export const SLEEP_COMMAND = 'kr host power --set'

/** The default local model, offered during setup. */
export interface ModelPackage {
  /** What it is called. */
  readonly name: string
  /** What it is for. */
  readonly purpose: string
  /** How big the download is, stated before it starts. */
  readonly bytes: number
}

/** The package setup offers. */
export const DEFAULT_MODEL: ModelPackage = {
  name: 'The default local model',
  purpose:
    'Summaries, titles and suggestions run on this machine instead of somewhere else. Nothing ' +
    'about KalaReach needs it.',
  bytes: 1_880_000_000
}

/** A size in the units a person reads. */
export function readableBytes(bytes: number): string {
  if (bytes < 1_000) return `${bytes} bytes`
  const units = ['kB', 'MB', 'GB', 'TB']
  let value = bytes / 1_000
  let unit = 0
  while (value >= 1_000 && unit < units.length - 1) {
    value /= 1_000
    unit += 1
  }
  return `${value.toFixed(value < 10 ? 1 : 0)} ${units[unit]}`
}

/** What a download is doing. */
export type DownloadState = 'offered' | 'downloading' | 'cancelled' | 'declined' | 'installed'

/** What the person is told a download is doing. */
export const DOWNLOAD_LABEL: Readonly<Record<DownloadState, string>> = {
  offered: 'Not downloaded',
  downloading: 'Downloading',
  cancelled: 'Cancelled',
  declined: 'Turned off',
  installed: 'Installed'
}

/**
 * The accounts an ordinary person needs to use this product.
 *
 * None. Section 26 says so and this is where the interface says it: the official applications and
 * the free gateway need no Cloudflare, Stripe, Firebase or Apple developer account, and setup
 * asks for none of them.
 */
export const ACCOUNTS_REQUIRED: readonly string[] = []

/** The sentence setup ends on. */
export const NO_ACCOUNT_NEEDED =
  'Setup asked you for no account. KalaReach works with no Cloudflare, Stripe, Firebase or Apple ' +
  'developer account: the applications and the shared gateway are free to use, and nothing on ' +
  'this screen signed you up for anything.'
