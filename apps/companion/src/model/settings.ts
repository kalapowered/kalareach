/**
 * Settings sync, in the words the page uses for it.
 *
 * The colour mode is the first setting. Native code keeps it on this computer, and when the person
 * turns settings sync on, keeps it sealed at the sync service so their other devices find it. The
 * page is told where that stands and how many copies of another device's settings wait for a
 * choice; the key, the identities and the content stay in native code.
 */

import type {
  ColourMode,
  KeptDrafts,
  SettingsChoice,
  SettingsKeep,
  SettingsSyncView
} from '../host/port'

/** What settings sync is, and what it is not. */
export const SETTINGS_SYNC_HELP =
  'Your colour mode follows you to your other devices. It is sealed on this device first, with a ' +
  'key only your devices hold, so the sync service keeps something it cannot read.'

/** The sentence a person reads first, for where settings sync stands. */
export function describeSettingsSync(sync: SettingsSyncView): string {
  switch (sync.state) {
    case 'off':
      return 'Your settings stay on this device.'
    case 'starting':
      return `Waiting for ${sync.kept_at ?? 'the sync service'} to start keeping your settings.`
    case 'on':
      return `Your settings are kept in step through ${sync.kept_at ?? 'the sync service'}.`
  }
}

/** What keeping drafts in step does, said where the person turns it on. */
export const DRAFTS_SYNC_HELP =
  'Your unsent prompts follow you to your other devices, sealed like your settings. A draft from ' +
  'another device is kept beside yours and is never sent.'

/** The drafts, counted: "1 draft", "3 drafts". */
function countDrafts(count: number): string {
  return count === 1 ? '1 draft' : `${count} drafts`
}

/** Why some drafts stay on this device and are not sent, in words. */
export function describeKeptHere(kept: KeptDrafts): string {
  const stays = kept.drafts === 1 ? 'stays' : 'stay'
  const place = kept.host === null ? 'that host' : kept.host
  switch (kept.why) {
    case 'private':
      return `${countDrafts(kept.drafts)} for ${place} ${stays} on this device while privacy mode is on there.`
    case 'unreadable':
      return (
        `${countDrafts(kept.drafts)} for ${place} ${stays} on this device because this device cannot ` +
        `read whether privacy mode is on there` +
        (kept.detail === null ? '.' : `: ${kept.detail}.`)
      )
    case 'unknown_host':
      return `${countDrafts(kept.drafts)} written while no host was connected ${stays} on this device.`
    case 'too_large':
      return `${countDrafts(kept.drafts)} ${kept.drafts === 1 ? 'is' : 'are'} too large to keep in step and ${stays} on this device.`
  }
}

/** What is waiting, other than a choice, when something is. Null when nothing is. */
export function describeWaiting(sync: SettingsSyncView): string | null {
  if (sync.paused) return 'Privacy mode has stopped settings from being sent.'
  if (sync.outstanding > 0) return 'A change was sent and has not been answered yet.'
  return null
}

/** What the colour mode is called. */
export function colourModeName(mode: ColourMode): string {
  switch (mode) {
    case 'light':
      return 'Light'
    case 'dark':
      return 'Dark'
    case 'system':
      return 'System'
  }
}

/** What two devices changed, and what the person is asked to do about it. */
export const SETTINGS_CHOICE_HELP =
  'You changed how KalaReach looks on this device, and another device changed it too. Nothing has ' +
  'been replaced. Keep one; the other is let go.'

/** One version the person can keep, in the words the choice shows it in. */
export interface Keepable {
  /** What chooses it: this device's own, or a copy another device wrote. */
  readonly keep: SettingsKeep
  /** A stable key. */
  readonly id: string
  /** The colour mode it holds, or null when this version cannot show it. */
  readonly mode: ColourMode | null
  /** Whose it is, in words. */
  readonly whose: string
  /** When the device that wrote it recorded it, formatted for a person, never used to order. */
  readonly recorded: string
}

/** The time a version was recorded, as a person reads it. */
export function recordedAt(ms: number): string {
  if (ms <= 0) return ''
  return new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(
    new Date(ms)
  )
}

/**
 * The versions to choose between: this device's own first, then each other device's in the order
 * this device received them. None is placed or marked for being later than another.
 */
export function keepables(choice: SettingsChoice): readonly Keepable[] {
  return [
    {
      keep: { choice: 'mine' },
      id: 'mine',
      mode: choice.mine.colour_mode,
      whose: 'This device',
      recorded: recordedAt(choice.mine.updated_at_ms)
    },
    ...choice.others.map((other) => ({
      keep: { choice: 'copy', conflict_id: other.conflict_id } as const,
      id: other.conflict_id,
      mode: other.colour_mode,
      whose: 'Another device',
      recorded: recordedAt(other.updated_at_ms)
    }))
  ]
}
